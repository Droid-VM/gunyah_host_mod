// SPDX-License-Identifier: GPL-2.0-only
/*
 * gunyah_halt_poll - halt polling for proxy-scheduled Gunyah vCPUs (GKI 6.6 built-in gunyah_vcpu)
 *
 * A guest vCPU that idles (WFI, or PSCI suspend) comes back from the vcpu_run hypercall as
 * EXPECTS_WAKEUP, and gunyah_vcpu_run() puts the VMM's vCPU thread to sleep in
 * wait_for_completion_interruptible(&vcpu->ready) at once. The interrupt that ends the idle --
 * an MSI or irqfd for a device completion, say -- then travels: doorbell -> Gunyah -> the host's
 * VCPU_RUN_WAKEUP interrupt (every one lands on CPU0) -> complete() -> the scheduler wakes the
 * thread on its own CPU -> vcpu_run again. A Windows guest takes that path thousands of times a
 * second, and an I/O completion waits through all of it.
 *
 * This is what KVM's halt_poll_ns avoids, and the same thing is done here: before the thread
 * sleeps, it spins for a while on the completion, so a wakeup that comes soon goes straight back
 * into the guest. How long it spins adapts per vCPU, as in KVM: it grows while wakeups arrive
 * shortly after the vCPU halted and shrinks when they do not, so an idle guest costs next to
 * nothing.
 *
 * The built-in driver is not modified. A kprobe on wait_for_completion_interruptible() redirects
 * the calls made from gunyah_vcpu_ioctl() (gunyah_vcpu_run() is inlined into it; it is checked
 * too, in case a kernel keeps it out of line) to gunyah_halt_poll_wait(), which polls and then
 * makes the real call. Every other caller in the kernel goes through untouched. As in KVM, a
 * poll ends as soon as another task is runnable on the CPU.
 *
 * Tunables (/sys/module/gunyah_halt_poll_gki_6.6/parameters/):
 *   halt_poll_ns         upper bound of a poll, ns (0 = off; KVM's default is 200000)
 *   halt_poll_grow       factor a vCPU's poll grows by
 *   halt_poll_grow_start first poll of a vCPU whose poll had shrunk to 0, ns
 *   halt_poll_shrink     divisor a vCPU's poll shrinks by (0 = straight to 0)
 * Counters: polls, poll_hits, poll_misses, poll_spent_ns (all spinning), wait_ns (sleeping).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <linux/hash.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/timekeeping.h>

static uint halt_poll_ns = 200000;
module_param(halt_poll_ns, uint, 0644);
MODULE_PARM_DESC(halt_poll_ns, "Longest a vCPU thread spins for a wakeup before it sleeps, ns (0 = off)");

static uint halt_poll_grow = 2;
module_param(halt_poll_grow, uint, 0644);
MODULE_PARM_DESC(halt_poll_grow, "Factor a vCPU's poll grows by");

static uint halt_poll_grow_start = 10000;
module_param(halt_poll_grow_start, uint, 0644);
MODULE_PARM_DESC(halt_poll_grow_start, "First poll of a vCPU whose poll had shrunk to 0, ns");

static uint halt_poll_shrink = 2;
module_param(halt_poll_shrink, uint, 0644);
MODULE_PARM_DESC(halt_poll_shrink, "Divisor a vCPU's poll shrinks by (0 = straight to 0)");

static atomic64_t stat_polls, stat_hits, stat_misses, stat_spent, stat_wait;

static int ghp_get_stat(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%lld\n", atomic64_read((atomic64_t *)kp->arg));
}

static const struct kernel_param_ops ghp_stat_ops = { .get = ghp_get_stat };
module_param_cb(polls, &ghp_stat_ops, &stat_polls, 0444);
module_param_cb(poll_hits, &ghp_stat_ops, &stat_hits, 0444);
module_param_cb(poll_misses, &ghp_stat_ops, &stat_misses, 0444);
module_param_cb(poll_spent_ns, &ghp_stat_ops, &stat_spent, 0444);
module_param_cb(wait_ns, &ghp_stat_ops, &stat_wait, 0444);

/* ------------------------------------------------------------------------- */
/* Per-vCPU poll length                                                        */
/* ------------------------------------------------------------------------- */

/*
 * Keyed by the vCPU's completion (&vcpu->ready, which lives as long as the vCPU). Entries are
 * never freed: a later vCPU whose completion lands at a freed one's address just starts from
 * that one's poll length, which adapts away within a few halts. When the table is full a vCPU
 * gets no slot and polls for halt_poll_grow_start without adapting.
 */
#define GHP_SLOTS 128

static struct {
	struct completion *key;
	unsigned int poll_ns;
} ghp_slots[GHP_SLOTS];

static unsigned int *ghp_slot(struct completion *x)
{
	unsigned int i, h = hash_ptr(x, 7);

	for (i = 0; i < GHP_SLOTS; i++) {
		unsigned int s = (h + i) % GHP_SLOTS;
		struct completion *key = READ_ONCE(ghp_slots[s].key);

		if (key == x)
			return &ghp_slots[s].poll_ns;
		if (!key && cmpxchg(&ghp_slots[s].key, NULL, x) == NULL) {
			WRITE_ONCE(ghp_slots[s].poll_ns, 0);
			return &ghp_slots[s].poll_ns;
		}
		if (READ_ONCE(ghp_slots[s].key) == x)
			return &ghp_slots[s].poll_ns;
	}
	return NULL;
}

/* KVM's rule (virt/kvm/kvm_main.c, kvm_vcpu_halt): grow while the vCPU was woken within the
 * bound but after its poll ended, shrink once a halt outlasts the bound. */
static void ghp_adapt(unsigned int *poll, u64 halted_ns)
{
	unsigned int max = READ_ONCE(halt_poll_ns), cur = READ_ONCE(*poll), val = cur;

	if (cur > max) {
		val = max;
	} else if (halted_ns <= cur) {
		return;
	} else if (halted_ns > max) {
		unsigned int shrink = READ_ONCE(halt_poll_shrink);

		val = shrink ? cur / shrink : 0;
	} else {
		unsigned int start = READ_ONCE(halt_poll_grow_start);

		val = cur ? cur * READ_ONCE(halt_poll_grow) : start;
		if (val < start)
			val = start;
		if (val > max)
			val = max;
	}
	WRITE_ONCE(*poll, val);
}

/* ------------------------------------------------------------------------- */
/* The redirected wait                                                         */
/* ------------------------------------------------------------------------- */

/*
 * single_task_running() is not in the GKI 6.6 export list (vmlinux has it, its __ksymtab entry is
 * trimmed), so it is resolved by name like the callers below. The prototype must stay exact: this
 * is an indirect call under CONFIG_CFI_CLANG. Without it a poll ends on need_resched() alone.
 */
static bool (*ghp_single_task_running)(void);

/*
 * Entered from the kprobe with x0 still holding wait_for_completion_interruptible()'s argument
 * and the return address still pointing into gunyah_vcpu_ioctl(), so this runs as if the driver
 * had called it. It returns what the real wait would have: 0 once the completion is done (taken
 * with try_wait_for_completion(), as the real wait takes it), -ERESTARTSYS on a signal.
 *
 * The module reference taken by the kprobe is held until the very end, across the real wait the
 * thread may sleep in for as long as its vCPU idles: rmmod is refused while a VM runs, instead of
 * pulling this code out from under a sleeping thread.
 */
static int gunyah_halt_poll_wait(struct completion *x)
{
	unsigned int *slot = ghp_slot(x);
	unsigned int max = READ_ONCE(halt_poll_ns);
	unsigned int poll = slot ? READ_ONCE(*slot) : READ_ONCE(halt_poll_grow_start);
	u64 start = ktime_get_mono_fast_ns(), now = start, end;
	int ret = 0;

	if (poll > max)
		poll = max;
	if (poll) {
		atomic64_inc(&stat_polls);
		end = start + poll;
		for (;;) {
			if (READ_ONCE(x->done) && try_wait_for_completion(x)) {
				now = ktime_get_mono_fast_ns();
				atomic64_inc(&stat_hits);
				atomic64_add(now - start, &stat_spent);
				goto out;
			}
			now = ktime_get_mono_fast_ns();
			/* As KVM's kvm_vcpu_can_poll(): stop as soon as anything else wants this
			 * CPU -- with every vCPU of a busy guest polling, the VMM's own device
			 * threads would otherwise wait out the polls for a core to complete on. */
			if (now >= end || need_resched() ||
			    (ghp_single_task_running && !ghp_single_task_running()) ||
			    signal_pending(current))
				break;
			cpu_relax();
		}
		atomic64_inc(&stat_misses);
		atomic64_add(now - start, &stat_spent);
	}

	ret = wait_for_completion_interruptible(x);
	end = ktime_get_mono_fast_ns();
	atomic64_add(end - now, &stat_wait);
	now = end;
out:
	if (slot && max)
		ghp_adapt(slot, now - start);
	module_put(THIS_MODULE);
	return ret;
}

/* ------------------------------------------------------------------------- */
/* Hook                                                                        */
/* ------------------------------------------------------------------------- */

static unsigned long (*ghp_lookup_name)(const char *name);
static int (*ghp_lookup_size_offset)(unsigned long addr, unsigned long *size, unsigned long *off);

/* Text ranges of the built-in callers whose waits are redirected. */
static struct {
	const char *name;
	unsigned long start, end;
} ghp_callers[] = {
	{ "gunyah_vcpu_ioctl" },
	{ "gunyah_vcpu_run" },
};

static atomic_t ghp_seen = ATOMIC_INIT(0);

static int ghp_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long lr = regs->regs[30];
	int i;

	if (!READ_ONCE(halt_poll_ns))
		return 0;
	for (i = 0; i < ARRAY_SIZE(ghp_callers); i++) {
		if (lr - ghp_callers[i].start < ghp_callers[i].end - ghp_callers[i].start)
			break;
	}
	if (i == ARRAY_SIZE(ghp_callers))
		return 0;
	/* Fails only while the module is being unloaded; the real wait then runs untouched. */
	if (!try_module_get(THIS_MODULE))
		return 0;
	if (atomic_inc_return(&ghp_seen) == 1)
		pr_info("first vCPU halt redirected (called from %ps)\n", (void *)lr);
	instruction_pointer_set(regs, (unsigned long)gunyah_halt_poll_wait);
	return 1;	/* do not execute the probed instruction */
}

static struct kprobe ghp_kp = {
	.symbol_name = "wait_for_completion_interruptible",
	.pre_handler = ghp_pre,
};

/* kallsyms_lookup_name has not been exported since 5.7; a kprobe on it yields its address. */
static int ghp_resolve(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	unsigned long size, off;
	int i, found = 0;

	if (register_kprobe(&kp) < 0)
		return -ENOENT;
	ghp_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);

	ghp_lookup_size_offset = (void *)ghp_lookup_name("kallsyms_lookup_size_offset");
	ghp_single_task_running = (void *)ghp_lookup_name("single_task_running");
	if (!ghp_single_task_running)
		pr_warn("single_task_running not found: polls stop on need_resched() only\n");
	if (!ghp_lookup_size_offset)
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(ghp_callers); i++) {
		unsigned long addr = ghp_lookup_name(ghp_callers[i].name);

		if (!addr || !ghp_lookup_size_offset(addr, &size, &off) || off)
			continue;
		ghp_callers[i].start = addr;
		ghp_callers[i].end = addr + size;
		pr_info("%s: %#lx bytes\n", ghp_callers[i].name, size);
		found++;
	}
	return found ? 0 : -ENOENT;
}

static int __init ghp_init(void)
{
	int ret = ghp_resolve();

	if (ret) {
		pr_err("the built-in gunyah_vcpu driver is not in this kernel\n");
		return ret;
	}
	ret = register_kprobe(&ghp_kp);
	if (ret) {
		pr_err("cannot probe wait_for_completion_interruptible: %d\n", ret);
		return ret;
	}
	pr_info("loaded: halt_poll_ns=%u\n", halt_poll_ns);
	return 0;
}

static void __exit ghp_exit(void)
{
	unregister_kprobe(&ghp_kp);
	pr_info("unloaded: %lld polls, %lld hits\n", atomic64_read(&stat_polls),
		atomic64_read(&stat_hits));
}

module_init(ghp_init);
module_exit(ghp_exit);
MODULE_DESCRIPTION("Halt polling for proxy-scheduled Gunyah vCPUs");
MODULE_LICENSE("GPL");
