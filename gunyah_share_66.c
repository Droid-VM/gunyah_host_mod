// SPDX-License-Identifier: GPL-2.0-only
/*
 * gunyah_share_66 — standalone out-of-tree runtime-SHARE module for the
 * *upstream* GKI 6.6 gunyah driver (android15-6.6). Reproduces an in-tree
 * "SHARE_BLOB" ioctl without patching drivers/virt/gunyah.
 *
 * Purpose: let crosvm SHARE an arbitrary userspace buffer (a host-visible
 * virtio-gpu blob backing) to a *running* protected guest as an RM memparcel,
 * and return the mem_handle. The guest then accepts it itself via a raw HVC
 * mem_accept (see guest gunyah_guest.ko) into its own stage-2 at the BAR GPA.
 * This is the "GuestAccept" path — no eager arena, no reserved-memory node,
 * no dtb_shim, and a clean per-blob accept/release/reclaim lifecycle.
 *
 * Why a module and not a kernel patch: the gunyah VM fd's ioctl switch
 * (gunyah_vm_ioctl) is static; we expose our own /dev/gunyah_share char device
 * and take the VM fd as a request field. The RM RPC helpers
 * (gunyah_rm_mem_share/reclaim) are global but NOT EXPORT_SYMBOL, so we resolve
 * them via kallsyms. struct gunyah_vm is private; we read vmid/rm by BTF-verified
 * byte offset (overridable via module params if a future build shifts them).
 *
 * FRAGILE BY DESIGN: pinned to this device's KMI (6.6.118-android15). Verify
 * the struct offsets against the target vmlinux.btf before trusting on another build.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/debugfs.h>
#include <linux/types.h>
#include <linux/bitops.h>

/* ---- UAPI (inlined; must match crosvm gunyah_sys bindings + l233 uapi) ---- */
#define GHSM_IOCTL_TYPE 0x47 /* 'G' */
struct ghsm_share_blob {
	__s32 vm_fd;
	__u32 label;
	__u32 flags;
	__u32 mem_handle;
	__u64 guest_phys_addr;
	__u64 memory_size;
	__u64 userspace_addr;
};
#define GHSM_SHARE_BLOB _IOWR(GHSM_IOCTL_TYPE, 0x14, struct ghsm_share_blob)
struct ghsm_unshare_blob {
	__s32 vm_fd;
	__u32 label;
};
#define GHSM_UNSHARE_BLOB _IOW(GHSM_IOCTL_TYPE, 0x15, struct ghsm_unshare_blob)

/* ---- vendored 6.6 RM types (match include/linux/gunyah.h @ 6.6.118) ---- */
enum gunyah_rm_mem_type { GUNYAH_RM_MEM_TYPE_NORMAL = 0, GUNYAH_RM_MEM_TYPE_IO = 1 };

struct gunyah_rm_mem_acl_entry {
	__le16 vmid;
	u8 perms;
	u8 reserved;
} __packed;

struct gunyah_rm_mem_entry {
	__le64 phys_addr;
	__le64 size;
} __packed;

struct gunyah_rm_mem_parcel {
	enum gunyah_rm_mem_type mem_type;
	u32 label;
	size_t n_acl_entries;
	struct gunyah_rm_mem_acl_entry *acl_entries;
	size_t n_mem_entries;
	struct gunyah_rm_mem_entry *mem_entries;
	u32 mem_handle;
};

#define GUNYAH_RM_ACL_X		BIT(0)
#define GUNYAH_RM_ACL_W		BIT(1)
#define GUNYAH_RM_ACL_R		BIT(2)
#define GUNYAH_MEM_HANDLE_INVAL	U32_MAX

/* crosvm/uapi mem-allow flags (uapi/linux/gunyah.h) */
#define GH_ALLOW_READ	(1u << 0)
#define GH_ALLOW_WRITE	(1u << 1)
#define GH_ALLOW_EXEC	(1u << 2)

/* struct gunyah_vm private-layout offsets (BTF vmlinux.btf, 6.6.118-android15). */
static int vmid_off = 0;	/* u16 gunyah_vm.vmid   */
static int rm_off   = 504;	/* struct gunyah_rm *gunyah_vm.rm */
module_param(vmid_off, int, 0444);
module_param(rm_off, int, 0444);

/* ---- resolved-at-load symbols ---- */
struct gunyah_rm;
static int (*p_rm_mem_share)(struct gunyah_rm *rm, struct gunyah_rm_mem_parcel *p);
static int (*p_rm_mem_reclaim)(struct gunyah_rm *rm, struct gunyah_rm_mem_parcel *p);
/* gunyah_rm_get_vmid is global (T) but NOT in the GKI module KMI whitelist, so
 * it cannot be linked; resolve it via kallsyms like the mem_share helpers. */
static int (*p_rm_get_vmid)(struct gunyah_rm *rm, u16 *vmid);
#define gunyah_rm_get_vmid(rm, vmid) p_rm_get_vmid((rm), (vmid))

static unsigned long lookup_name(const char *name)
{
	static unsigned long (*kln)(const char *);
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	if (!kln) {
		if (register_kprobe(&kp))
			return 0;
		kln = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
	return kln ? kln(name) : 0;
}

/* ---- tracked live parcels (per (vm,label)) so we can reclaim + unpin ---- */
struct ghsm_map {
	struct list_head node;
	void *ghvm;			/* struct gunyah_vm* (identity only) */
	struct file *vm_file;		/* pins the VM file so ghvm/rm stay valid
					 * even after crosvm exits; dropped when
					 * the parcel is reclaimed (unshare/exit) */
	u32 label;
	struct page **pages;
	unsigned long npages;
	struct gunyah_rm_mem_parcel parcel;
};
static LIST_HEAD(ghsm_maps);
static DEFINE_MUTEX(ghsm_lock);

static struct ghsm_map *find_map(void *ghvm, u32 label)
{
	struct ghsm_map *m;
	list_for_each_entry(m, &ghsm_maps, node)
		if (m->ghvm == ghvm && m->label == label)
			return m;
	return NULL;
}

/* Resolve a userspace gunyah VM fd to its struct gunyah_vm*, validated by the
 * anon-inode name "gunyah-vm" (anon_inode_getfile in vm_mgr.c). Returns the file
 * (caller must fput) via *out_file, and the ghvm pointer. */
static void *ghsm_get_ghvm(int vm_fd, struct file **out_file)
{
	struct file *f = fget(vm_fd);
	if (!f)
		return NULL;
	if (!f->f_path.dentry ||
	    strcmp(f->f_path.dentry->d_name.name, "gunyah-vm") != 0) {
		fput(f);
		return NULL;
	}
	*out_file = f;
	return f->private_data;
}

static inline u16 ghvm_vmid(void *ghvm) { return *(u16 *)((u8 *)ghvm + vmid_off); }
static inline struct gunyah_rm *ghvm_rm(void *ghvm)
{
	return *(struct gunyah_rm **)((u8 *)ghvm + rm_off);
}

static u8 flags_to_perms(u32 flags)
{
	u8 p = 0;
	if (flags & GH_ALLOW_READ)  p |= GUNYAH_RM_ACL_R;
	if (flags & GH_ALLOW_WRITE) p |= GUNYAH_RM_ACL_W;
	if (flags & GH_ALLOW_EXEC)  p |= GUNYAH_RM_ACL_X;
	return p;
}

/* Core: pin the userspace buffer, build a SHARE parcel (guest keeps host access),
 * hand it to the RM, return the handle. Mirrors gunyah_gup_share_parcel. */
static int ghsm_share(void *ghvm, struct file *vmf, struct gunyah_rm *rm,
		      u32 label, u32 flags, u64 uaddr, u64 size, u32 *out_handle)
{
	unsigned long npages, i, n_entries, entry;
	struct page **pages;
	struct ghsm_map *m;
	u16 guest_vmid, host_vmid;
	unsigned int gup_flags;
	u64 run_size;
	long pinned;
	int ret;

	if (!IS_ALIGNED(uaddr, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE) || !size)
		return -EINVAL;
	npages = size >> PAGE_SHIFT;

	mutex_lock(&ghsm_lock);
	if (find_map(ghvm, label)) {
		mutex_unlock(&ghsm_lock);
		return -EBUSY;		/* guest must UNSHARE the old parcel first */
	}
	mutex_unlock(&ghsm_lock);

	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL_ACCOUNT);
	if (!pages)
		return -ENOMEM;

	gup_flags = FOLL_LONGTERM;
	if (flags & GH_ALLOW_WRITE)
		gup_flags |= FOLL_WRITE;
	pinned = pin_user_pages_fast(uaddr, npages, gup_flags, pages);
	if (pinned < 0) { ret = pinned; goto free_pages; }
	if (pinned != npages) { ret = -EFAULT; goto unpin; }

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m) { ret = -ENOMEM; goto unpin; }
	m->ghvm = ghvm; m->label = label; m->pages = pages; m->npages = npages;
	m->vm_file = get_file(vmf);

	/* SHARE: 2 ACL entries — guest (from flags) + host (RWX). */
	guest_vmid = ghvm_vmid(ghvm);
	ret = gunyah_rm_get_vmid(rm, &host_vmid);
	if (ret) goto free_m;

	m->parcel.mem_type = GUNYAH_RM_MEM_TYPE_NORMAL;
	m->parcel.label = label;
	m->parcel.mem_handle = GUNYAH_MEM_HANDLE_INVAL;
	m->parcel.n_acl_entries = 2;
	m->parcel.acl_entries = kcalloc(2, sizeof(*m->parcel.acl_entries), GFP_KERNEL);
	if (!m->parcel.acl_entries) { ret = -ENOMEM; goto free_m; }
	m->parcel.acl_entries[0].vmid = cpu_to_le16(guest_vmid);
	m->parcel.acl_entries[0].perms = flags_to_perms(flags);
	m->parcel.acl_entries[1].vmid = cpu_to_le16(host_vmid);
	m->parcel.acl_entries[1].perms = GUNYAH_RM_ACL_R | GUNYAH_RM_ACL_W | GUNYAH_RM_ACL_X;

	/* Coalesce physically-contiguous page runs into single mem_entries.
	 * THP/mthp-backed buffers (2MB folios) collapse 512:1, which is what
	 * keeps large blobs under the RM's per-parcel resource limits. */
	n_entries = 1;
	for (i = 1; i < npages; i++) {
		if (page_to_phys(pages[i]) != page_to_phys(pages[i - 1]) + PAGE_SIZE)
			n_entries++;
	}
	m->parcel.n_mem_entries = n_entries;
	m->parcel.mem_entries = kcalloc(n_entries, sizeof(*m->parcel.mem_entries),
					GFP_KERNEL_ACCOUNT);
	if (!m->parcel.mem_entries) { ret = -ENOMEM; goto free_acl; }
	entry = 0;
	m->parcel.mem_entries[0].phys_addr = cpu_to_le64(page_to_phys(pages[0]));
	run_size = PAGE_SIZE;
	for (i = 1; i < npages; i++) {
		if (page_to_phys(pages[i]) == page_to_phys(pages[i - 1]) + PAGE_SIZE) {
			run_size += PAGE_SIZE;
			continue;
		}
		m->parcel.mem_entries[entry].size = cpu_to_le64(run_size);
		entry++;
		m->parcel.mem_entries[entry].phys_addr =
			cpu_to_le64(page_to_phys(pages[i]));
		run_size = PAGE_SIZE;
	}
	m->parcel.mem_entries[entry].size = cpu_to_le64(run_size);

	ret = p_rm_mem_share(rm, &m->parcel);
	if (ret) {
		pr_err("gunyah_share_66: rm_mem_share label=%u ret=%d\n", label, ret);
		goto free_entries;
	}

	*out_handle = m->parcel.mem_handle;
	mutex_lock(&ghsm_lock);
	list_add(&m->node, &ghsm_maps);
	mutex_unlock(&ghsm_lock);
	pr_info("gunyah_share_66: SHARE label=%u gpa_pages=%lu entries=%lu guest_vmid=%u handle=0x%x\n",
		label, npages, n_entries, guest_vmid, *out_handle);
	return 0;

free_entries:
	kfree(m->parcel.mem_entries);
free_acl:
	kfree(m->parcel.acl_entries);
free_m:
	fput(m->vm_file);
	kfree(m);
unpin:
	unpin_user_pages(pages, pinned > 0 ? pinned : 0);
free_pages:
	kfree(pages);
	return ret;
}

static int ghsm_unshare(void *ghvm, struct gunyah_rm *rm, u32 label)
{
	struct ghsm_map *m;
	int ret;

	mutex_lock(&ghsm_lock);
	m = find_map(ghvm, label);
	if (m)
		list_del(&m->node);
	mutex_unlock(&ghsm_lock);
	if (!m)
		return -ENOENT;

	ret = p_rm_mem_reclaim(rm, &m->parcel);
	if (ret)
		pr_warn("gunyah_share_66: rm_mem_reclaim label=%u ret=%d\n", label, ret);
	unpin_user_pages(m->pages, m->npages);
	fput(m->vm_file);
	kfree(m->pages);
	kfree(m->parcel.acl_entries);
	kfree(m->parcel.mem_entries);
	kfree(m);
	pr_info("gunyah_share_66: UNSHARE label=%u ret=%d\n", label, ret);
	return ret;
}

/* ---- /dev/gunyah_share char device ---- */
static long ghsm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct file *vmf = NULL;
	void *ghvm;
	struct gunyah_rm *rm;
	long ret;

	switch (cmd) {
	case GHSM_SHARE_BLOB: {
		struct ghsm_share_blob b;
		u32 handle = 0;
		if (copy_from_user(&b, (void __user *)arg, sizeof(b)))
			return -EFAULT;
		ghvm = ghsm_get_ghvm(b.vm_fd, &vmf);
		if (!ghvm) return -EINVAL;
		rm = ghvm_rm(ghvm);
		ret = ghsm_share(ghvm, vmf, rm, b.label, b.flags,
				 b.userspace_addr, b.memory_size, &handle);
		fput(vmf);
		if (ret) return ret;
		b.mem_handle = handle;
		if (copy_to_user((void __user *)arg, &b, sizeof(b)))
			return -EFAULT;
		return 0;
	}
	case GHSM_UNSHARE_BLOB: {
		struct ghsm_unshare_blob b;
		if (copy_from_user(&b, (void __user *)arg, sizeof(b)))
			return -EFAULT;
		ghvm = ghsm_get_ghvm(b.vm_fd, &vmf);
		if (!ghvm) return -EINVAL;
		rm = ghvm_rm(ghvm);
		ret = ghsm_unshare(ghvm, rm, b.label);
		fput(vmf);
		return ret;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ghsm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ghsm_ioctl,
	.compat_ioctl = ghsm_ioctl,
};
static struct miscdevice ghsm_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "gunyah_share",
	.fops = &ghsm_fops,
	.mode = 0600,
};

/* ---- debugfs probe for standalone bring-up (no crosvm): ----
 *   echo "<vm_fd> <size_hex> <label>" > /sys/kernel/debug/gh_share_probe
 * runs in the echoing process's fd table, so that process must hold the VM fd.
 * Allocates size bytes, fills a magic pattern, SHAREs to the guest, prints the
 * handle+gpa-agnostic parcel (the guest accepts by handle). Intentionally leaks
 * the pages so the guest can accept and read them. */
static struct dentry *ghsm_dbg;
static ssize_t gsp_write(struct file *f, const char __user *ub, size_t len, loff_t *off)
{
	char buf[64]; int vm_fd; u64 size; u32 label, handle = 0, *p; unsigned long i;
	struct file *vmf = NULL; void *ghvm; struct gunyah_rm *rm; long ret;
	void *va; struct page **pages; unsigned long npages;

	if (len >= sizeof(buf)) return -EINVAL;
	if (copy_from_user(buf, ub, len)) return -EFAULT;
	buf[len] = 0;
	if (sscanf(buf, "%d %llx %u", &vm_fd, &size, &label) != 3) return -EINVAL;
	size = PAGE_ALIGN(size);
	npages = size >> PAGE_SHIFT;

	ghvm = ghsm_get_ghvm(vm_fd, &vmf);
	if (!ghvm) return -EINVAL;
	rm = ghvm_rm(ghvm);

	va = vmalloc_user(size);		/* page-aligned, user-mappable */
	if (!va) { fput(vmf); return -ENOMEM; }
	p = va;
	for (i = 0; i < size / 4; i++) p[i] = 0xA5A50000u | (u32)i;  /* magic */

	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL);
	if (!pages) { vfree(va); fput(vmf); return -ENOMEM; }
	for (i = 0; i < npages; i++) pages[i] = vmalloc_to_page(va + i * PAGE_SIZE);

	{
		struct ghsm_map *m = kzalloc(sizeof(*m), GFP_KERNEL);
		u16 gvm = ghvm_vmid(ghvm), hvm;
		if (!m) { kfree(pages); vfree(va); fput(vmf); return -ENOMEM; }
		if (gunyah_rm_get_vmid(rm, &hvm)) { kfree(m); kfree(pages); vfree(va); fput(vmf); return -EIO; }
		m->parcel.mem_type = GUNYAH_RM_MEM_TYPE_NORMAL;
		m->parcel.label = label;
		m->parcel.mem_handle = GUNYAH_MEM_HANDLE_INVAL;
		m->parcel.n_acl_entries = 2;
		m->parcel.acl_entries = kcalloc(2, sizeof(struct gunyah_rm_mem_acl_entry), GFP_KERNEL);
		m->parcel.acl_entries[0].vmid = cpu_to_le16(gvm);
		m->parcel.acl_entries[0].perms = GUNYAH_RM_ACL_R | GUNYAH_RM_ACL_W;
		m->parcel.acl_entries[1].vmid = cpu_to_le16(hvm);
		m->parcel.acl_entries[1].perms = GUNYAH_RM_ACL_R | GUNYAH_RM_ACL_W | GUNYAH_RM_ACL_X;
		m->parcel.n_mem_entries = npages;
		m->parcel.mem_entries = kcalloc(npages, sizeof(struct gunyah_rm_mem_entry), GFP_KERNEL);
		for (i = 0; i < npages; i++) {
			m->parcel.mem_entries[i].phys_addr = cpu_to_le64(page_to_phys(pages[i]));
			m->parcel.mem_entries[i].size = cpu_to_le64(PAGE_SIZE);
		}
		ret = p_rm_mem_share(rm, &m->parcel);
		handle = m->parcel.mem_handle;
		pr_info("GSP: SHARE probe vm_fd=%d guest_vmid=%u size=0x%llx label=%u => ret=%ld handle=0x%x magic=0xA5A5xxxx (LEAKED for guest accept)\n",
			vm_fd, gvm, size, label, ret, handle);
		/* leak m/pages/va intentionally */
	}
	kfree(pages);		/* the pages[] array; underlying vmalloc pages stay pinned by parcel */
	fput(vmf);
	return ret ? ret : len;
}
static const struct file_operations gsp_fops = { .owner = THIS_MODULE, .write = gsp_write };

static int __init ghsm_init(void)
{
	int ret;
	p_rm_mem_share = (void *)lookup_name("gunyah_rm_mem_share");
	p_rm_mem_reclaim = (void *)lookup_name("gunyah_rm_mem_reclaim");
	p_rm_get_vmid = (void *)lookup_name("gunyah_rm_get_vmid");
	if (!p_rm_mem_share || !p_rm_mem_reclaim || !p_rm_get_vmid) {
		pr_err("gunyah_share_66: cannot resolve gunyah_rm_mem_share/reclaim/get_vmid (gunyah loaded first?)\n");
		return -ENOENT;
	}
	ret = misc_register(&ghsm_dev);
	if (ret) return ret;
	ghsm_dbg = debugfs_create_file("gh_share_probe", 0200, NULL, NULL, &gsp_fops);
	pr_info("gunyah_share_66: loaded (share=%px reclaim=%px vmid_off=%d rm_off=%d)\n",
		p_rm_mem_share, p_rm_mem_reclaim, vmid_off, rm_off);
	return 0;
}
static void __exit ghsm_exit(void)
{
	struct ghsm_map *m, *tmp;
	debugfs_remove(ghsm_dbg);
	misc_deregister(&ghsm_dev);
	mutex_lock(&ghsm_lock);
	list_for_each_entry_safe(m, tmp, &ghsm_maps, node) {
		list_del(&m->node);
		p_rm_mem_reclaim(ghvm_rm(m->ghvm), &m->parcel);
		unpin_user_pages(m->pages, m->npages);
		fput(m->vm_file);
		kfree(m->pages); kfree(m->parcel.acl_entries);
		kfree(m->parcel.mem_entries); kfree(m);
	}
	mutex_unlock(&ghsm_lock);
	pr_info("gunyah_share_66: unloaded\n");
}
module_init(ghsm_init);
module_exit(ghsm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Standalone runtime SHARE_BLOB for upstream gunyah 6.6 (GuestAccept)");
