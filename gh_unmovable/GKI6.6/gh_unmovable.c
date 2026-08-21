// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * gh_unmovable -- non-movable, FOLL_LONGTERM-pinnable userspace memory for
 * DroidVM's SMALL host-visible GPU blobs.
 *
 * Why: the gh_hugepage reserve keeps a big defragmented block that only accepts
 * MOVABLE allocations (so the phone can lend it to Android apps when no VM runs,
 * and reclaim it as isolated 2MB folios for the VM). Large GPU blobs take those
 * isolated (pinnable) folios. But SMALL blobs (< the folio threshold) bypass the
 * reserve and get plain shmem pages, which the kernel places in MOVABLE/CMA
 * pageblocks. gunyah_share then does pin_user_pages_fast(FOLL_LONGTERM); that
 * cannot pin a MOVABLE/CMA page, so it tries to migrate it to a non-movable zone
 * first -- and when that zone is tight the migration ENOMEMs, the SHARE fails
 * (-12), and the guest mmap of the blob returns EINVAL / VK_ERROR_OUT_OF_DEVICE_
 * MEMORY. Empirically every runtime-share small blob dies this way unless the
 * reserve's CMA is manually reclaimed first.
 *
 * Fix: hand small blobs pages that are born NON-movable -- alloc_page(GFP_KERNEL)
 * has no __GFP_MOVABLE, so the pages land in an UNMOVABLE pageblock and
 * FOLL_LONGTERM pins them with ZERO migration (the failing path is never taken).
 * These come from ZONE_NORMAL's unmovable/reclaimable free (falling back to
 * stealing movable pageblocks) -- the already-fragmented memory OUTSIDE the
 * reserve, useless for 2MB-contiguous anyway; the isolated 2MB reserve is never
 * touched, so VM-anytime-startability is preserved. Pages are released on the
 * final fput (all mmaps unmapped + fd closed), so nothing is left pinned.
 *
 * Usage: open("/dev/gh_unmovable", O_RDWR); mmap(NULL, size, PROT_READ|WRITE,
 * MAP_SHARED, fd, 0). The backing is allocated on the first mmap; further mmaps
 * of the same fd (e.g. crosvm re-mapping the fd gfxstream passed it) share the
 * same pages, exactly like a memfd. No ftruncate needed -- size comes from mmap.
 */

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/version.h>

/* 6.12 encapsulated struct fd behind fd_file(); pre-6.12 exposes .file. This
 * one source builds for GKI 6.1 / 6.6 / 6.12 (see build.sh). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#define fd_file(f) ((f).file)
#endif

#define GHU_MAX_BYTES (256UL << 20) /* per-fd sanity cap: small blobs only */

/*
 * Primary interface for the udmabuf path: GH_UNMOVABLE_MAKE takes an existing
 * memfd (arg = its fd) and drops __GFP_MOVABLE from its address_space gfp mask,
 * so every page shmem later faults in for it (e.g. when udmabuf pins them, or
 * gunyah_share LONGTERM-pins them) is born in a NON-movable pageblock -- no
 * migration, no CMA, the -12 pin failure path is never taken. Call it right
 * after memfd_create/ftruncate and BEFORE the memfd is faulted (udmabuf create).
 */
#define GH_UNMOVABLE_IOC_MAGIC 'H'
#define GH_UNMOVABLE_MAKE _IO(GH_UNMOVABLE_IOC_MAGIC, 1) /* arg = memfd fd */

struct ghu_ctx {
	struct mutex	lock;
	struct page   **pages; /* kvcalloc'd; each an order-0 non-movable page */
	unsigned long	npages;
};

static int ghu_open(struct inode *ino, struct file *f)
{
	struct ghu_ctx *c = kzalloc(sizeof(*c), GFP_KERNEL);

	if (!c)
		return -ENOMEM;
	mutex_init(&c->lock);
	f->private_data = c;
	return 0;
}

static void ghu_release_pages(struct ghu_ctx *c)
{
	unsigned long i;

	if (!c->pages)
		return;
	/* Drop our own ref. Any VMA / GUP refs were released before .release runs
	 * (an active mmap holds a file ref via vma->vm_file), so this is the last
	 * ref and the page frees back to the buddy allocator -- no permanent
	 * unmovable taint as long as the caller unmapped cleanly. */
	for (i = 0; i < c->npages; i++)
		if (c->pages[i])
			put_page(c->pages[i]);
	kvfree(c->pages);
	c->pages = NULL;
	c->npages = 0;
}

static int ghu_release(struct inode *ino, struct file *f)
{
	struct ghu_ctx *c = f->private_data;

	if (c) {
		ghu_release_pages(c);
		kfree(c);
	}
	return 0;
}

/* Allocate npages non-movable pages once per fd; a second mmap of the same fd
 * must request the same size (it re-maps the existing pages). */
static int ghu_ensure_pages(struct ghu_ctx *c, unsigned long npages)
{
	unsigned long i;

	if (c->pages)
		return (npages == c->npages) ? 0 : -EINVAL;

	c->pages = kvcalloc(npages, sizeof(*c->pages), GFP_KERNEL);
	if (!c->pages)
		return -ENOMEM;

	for (i = 0; i < npages; i++) {
		struct page *p = alloc_page(GFP_KERNEL | __GFP_ZERO);

		if (!p) {
			while (i--)
				put_page(c->pages[i]);
			kvfree(c->pages);
			c->pages = NULL;
			return -ENOMEM;
		}
		c->pages[i] = p;
	}
	c->npages = npages;
	return 0;
}

static int ghu_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct ghu_ctx *c = f->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long npages = size >> PAGE_SHIFT;
	unsigned long i;
	int ret;

	if (!c || vma->vm_pgoff || size == 0 || size > GHU_MAX_BYTES)
		return -EINVAL;

	mutex_lock(&c->lock);
	ret = ghu_ensure_pages(c, npages);
	if (ret)
		goto out;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	/* vm_insert_page -> VM_MIXEDMAP with normal refcounted pages, so GUP
	 * (pin_user_pages_fast, FOLL_LONGTERM) can pin them; VM_PFNMAP would block
	 * GUP, so we deliberately do NOT use remap_pfn_range. */
	for (i = 0; i < npages; i++) {
		ret = vm_insert_page(vma, vma->vm_start + (i << PAGE_SHIFT),
				     c->pages[i]);
		if (ret)
			break; /* the caller's munmap tears down the partial VMA */
	}
out:
	mutex_unlock(&c->lock);
	return ret;
}

/* Make a passed memfd's future page allocations non-movable (udmabuf path). */
static long ghu_make_unmovable(unsigned long arg)
{
	struct fd tf = fdget((unsigned int)arg);
	long ret = 0;

	if (!fd_file(tf))
		return -EBADF;
	if (!fd_file(tf)->f_mapping) {
		ret = -EINVAL;
		goto out;
	}
	/* GFP_HIGHUSER == GFP_HIGHUSER_MOVABLE without __GFP_MOVABLE. The caller
	 * (gfxstream) only passes freshly-created memfds, so future faults on this
	 * mapping (udmabuf pin, then gunyah_share's FOLL_LONGTERM pin) land in an
	 * UNMOVABLE pageblock instead of MOVABLE/CMA. (shmem_mapping() would be the
	 * precise check but its shmem_aops symbol isn't in the GKI 6.6 KMI.) */
	mapping_set_gfp_mask(fd_file(tf)->f_mapping, GFP_HIGHUSER);
out:
	fdput(tf);
	return ret;
}

static long ghu_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case GH_UNMOVABLE_MAKE:
		return ghu_make_unmovable(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ghu_fops = {
	.owner		= THIS_MODULE,
	.open		= ghu_open,
	.release	= ghu_release,
	.mmap		= ghu_mmap,
	.unlocked_ioctl	= ghu_ioctl,
	.compat_ioctl	= ghu_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice ghu_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "gh_unmovable",
	.fops  = &ghu_fops,
	.mode  = 0666,
};

/* ------------------------------------------------------------------ */
/* /dev/gh_pinprobe -- read-only "can this range be long-term pinned?"  */
/* ------------------------------------------------------------------ */
/*
 * Why a probe and not just a pin: every gunyah memory transfer (boot LEND of guest RAM,
 * boot SHARE of the GPU pools, runtime SHARE of a blob) ends in
 * pin_user_pages_fast(FOLL_LONGTERM). A page in a CMA (or isolate, or ZONE_MOVABLE)
 * pageblock cannot be pinned that way -- the kernel migrates it out first, and when there
 * is nothing to migrate into, that step fails deep inside the hypervisor call. Observed
 * outcomes of failing there: a multi-minute whole-host stall ending in the kernel
 * OOM-killing crosvm, and a "qcom_scm: Assign memory protection call failed -22" that
 * reset the phone.
 *
 * As long as the gh_hugepage reserve serves the whole region this never arises (its folios
 * are already pinnable). So the useful question at the decision point is not "pin it" but
 * "is any of it in a pageblock that would need migrating?" -- which is a property of the
 * pages, readable without taking a long-term reference, without migrating anything, and
 * without any of the reclaim pressure that makes the real thing dangerous.
 *
 * Sampling: migratetype is a per-pageblock property (pageblock is >= 2MB on every config
 * here), and the caller's regions are built out of 2MB folios, so one sample per 2MB
 * covers every pageblock in the range. The reference taken is short-lived and never
 * FOLL_LONGTERM, so nothing is migrated, and it is dropped immediately.
 *
 * It is also FOLL_NOFAULT, and that matters as much as the rest: get_user_pages() with no
 * flags FAULTS AN ABSENT PAGE IN. Asked about a region that has not been populated yet,
 * this probe therefore used to populate it -- one 4 KB page per 2 MB sample, order-0,
 * which the gh_hugepage reserve's hook does not intercept (it replaces order-9
 * allocations only). Those pages came from the buddy allocator, could land in CMA, and
 * were then dutifully reported as unpinnable: the probe was measuring what it had itself
 * just created, and no amount of waiting could clear it. Looking without populating is the
 * whole contract here. Absent pages are counted separately, never faulted in.
 */
/*
 * "Look, do not populate." FOLL_NOFAULT is 5.17+ and public on every KMI this module is
 * built for (6.1, 6.6, 6.12) -- a macro on 6.1 and an enumerator from 6.5, which is why
 * this is used unconditionally rather than guarded with #ifdef: the guard would silently
 * miss the enum. FOLL_FAST_ONLY would say the same thing, but it moved into mm/internal.h
 * in 6.5 and is not available to a module at all. If some future kernel refuses the flag,
 * every sample comes back absent -- which reads as "I could not tell", not as a false
 * all-clear -- and the module says so once in the log.
 */
#define GHP_FOLL_LOOK_ONLY FOLL_NOFAULT

#define GH_PINPROBE_IOC_MAGIC 'P'

struct gh_pinprobe_range {
	__u64 addr;		/* in:  user VA (page aligned) */
	__u64 len;		/* in:  bytes */
	__u64 samples;		/* out: pageblock samples taken */
	__u64 samples_cma;	/* out: samples in a MIGRATE_CMA pageblock */
	__u64 samples_isolate;	/* out: samples in a MIGRATE_ISOLATE pageblock */
	__u64 samples_movable;	/* out: samples in ZONE_MOVABLE */
	__u64 samples_absent;	/* out: samples with no page present */
	__u64 first_bad_offset;	/* out: byte offset of the first unpinnable sample, ~0 if none */
	__u32 sample_bytes;	/* out: distance between samples */
	__u32 flags;		/* in/out: reserved, must be 0 */
};

#define GH_PINPROBE_RANGE _IOWR(GH_PINPROBE_IOC_MAGIC, 1, struct gh_pinprobe_range)

#define GHP_SAMPLE_BYTES (2UL << 20)	/* one sample per 2MB */

/* Returns 1 if a page in this state would force migration before a FOLL_LONGTERM pin. */
static bool ghp_classify(struct page *page, struct gh_pinprobe_range *r)
{
	bool bad = false;
	int mt;

	mt = get_pageblock_migratetype(page);
#ifdef CONFIG_CMA
	if (mt == MIGRATE_CMA) {
		r->samples_cma++;
		bad = true;
	}
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	if (mt == MIGRATE_ISOLATE) {
		r->samples_isolate++;
		bad = true;
	}
#endif
	if (page_zonenum(page) == ZONE_MOVABLE) {
		r->samples_movable++;
		bad = true;
	}
	return bad;
}

static long ghp_probe(unsigned long arg)
{
	struct gh_pinprobe_range r;
	unsigned int gup_flags;
	unsigned long off, end;
	long ret = 0;

	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	if (!r.len || r.flags || (r.addr & ~PAGE_MASK))
		return -EINVAL;

	end = r.len;
	r.samples = 0;
	r.samples_cma = 0;
	r.samples_isolate = 0;
	r.samples_movable = 0;
	r.samples_absent = 0;
	gup_flags = GHP_FOLL_LOOK_ONLY;
	r.first_bad_offset = ~0ULL;
	r.sample_bytes = GHP_SAMPLE_BYTES;

	for (off = 0; off < end; off += GHP_SAMPLE_BYTES) {
		unsigned long va = (unsigned long)r.addr + off;
		struct page *page = NULL;
		int got;

		if (fatal_signal_pending(current))
			return -EINTR;

		/* Look, never populate, never migrate (see the header comment). */
		got = get_user_pages_fast(va, 1, gup_flags, &page);
		if (got == -EINVAL)
			pr_warn_once("pinprobe: kernel rejected FOLL_NOFAULT; every sample will "
				     "read as absent\n");
		if (got != 1) {
			r.samples_absent++;
			r.samples++;
			continue;
		}
		r.samples++;
		if (ghp_classify(page, &r) && r.first_bad_offset == ~0ULL)
			r.first_bad_offset = off;
		put_page(page);
		cond_resched();
	}

	if (copy_to_user((void __user *)arg, &r, sizeof(r)))
		ret = -EFAULT;
	return ret;
}

static long ghp_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case GH_PINPROBE_RANGE:
		return ghp_probe(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ghp_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ghp_ioctl,
	.compat_ioctl	= ghp_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice ghp_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "gh_pinprobe",
	.fops  = &ghp_fops,
	.mode  = 0666,
};

static int __init ghu_init(void)
{
	int ret = misc_register(&ghu_dev);

	if (ret) {
		pr_err("gh_unmovable: misc_register failed: %d\n", ret);
		return ret;
	}
	pr_info("gh_unmovable: /dev/gh_unmovable ready (non-movable pinnable mem)\n");

	/* Independent node, independent fops: the probe answers a different question and
	 * shares no state with the allocator above. Its absence must not take the
	 * allocator with it, so a failure here is a warning, not an error. */
	ret = misc_register(&ghp_dev);
	if (ret)
		pr_warn("gh_unmovable: /dev/gh_pinprobe unavailable: %d\n", ret);
	else
		pr_info("gh_unmovable: /dev/gh_pinprobe ready (longterm-pinnability probe)\n");
	return 0;
}

static void __exit ghu_exit(void)
{
	misc_deregister(&ghp_dev);
	misc_deregister(&ghu_dev);
}

module_init(ghu_init);
module_exit(ghu_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DroidVM: non-movable pinnable memory (/dev/gh_unmovable) + longterm-pinnability probe (/dev/gh_pinprobe)");
MODULE_AUTHOR("DroidVM");
