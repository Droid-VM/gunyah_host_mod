// SPDX-License-Identifier: GPL-2.0
/*
 * udmabuf_kv - one module that gives every host kernel a udmabuf good enough
 * for gfxstream, whatever state its built-in driver is in.  It picks ONE of
 * three modes at insmod and logs which:
 *
 *   native  - no built-in provider (CONFIG_UDMABUF unset): register /dev/udmabuf
 *             ourselves.  The driver below is the upstream one, version-gated
 *             for 6.1 / 6.6+, with the page-pointer array allocated by
 *             kvmalloc from the start.
 *   hijack  - built-in provider present but UNFIXED (allocates the page-pointer
 *             array with kmalloc_array, so a 128 MiB dma-buf needs a contiguous
 *             order-6 allocation and fails once memory is fragmented - the bug
 *             fixed upstream for the folio driver as CVE-2024-56544).  A kprobe
 *             redirects the built-in udmabuf_create() to ours.
 *   noop    - built-in provider present and already fixed (or too new / not
 *             safely hookable): the module loads and does nothing.
 *
 * The hijack replacement returns a dma_buf that is entirely OURS - our
 * dma_buf_ops, our private struct - so the built-in driver's own ops never see
 * our objects and we never see its private struct.  That is what makes hooking
 * one function enough: no vendored `struct udmabuf` layout to get wrong, and no
 * paired release_udmabuf hook (a kvmalloc'd pointer can never reach the
 * built-in kfree path, because the built-in release only ever runs for buffers
 * the built-in create made).  Buffers made before/after the hook is installed
 * are each freed by whoever made them.
 *
 * Every kernel function that is not part of the GKI module KMI is looked up by
 * name at runtime and simply left NULL when absent (same discipline as
 * gh_hugepage_reserve's kapi): a missing symbol degrades or disables a mode, it
 * never faults.  Nothing here dereferences a symbol it did not resolve.
 *
 * Differences from the in-tree driver, in every mode:
 *   - hugetlbfs memfds are rejected (6.6 upstream dropped them too; 6.1 loses
 *     that support here).  Only tmpfs/shmem memfds are accepted.
 *   - size_limit_mb defaults to 4096, and its page limit is computed in u64:
 *     upstream's int math overflows at >= 4096 (16384 -> 2^34 truncates to 0,
 *     rejecting everything).  In hijack mode this parameter, not the built-in's
 *     size_limit_mb, is the one that counts.
 */

#define pr_fmt(fmt) "udmabuf_kv: " fmt

#include <linux/version.h>

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/scatterlist.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/udmabuf.h>
#include <uapi/linux/fcntl.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#include <linux/dma-resv.h>
#include <linux/iosys-map.h>
#include <linux/vmalloc.h>
#endif

/* The folio-based rewrite (6.10) carries the kvmalloc fix and a create() we
 * must not stand in for.  Both this build-time bound and a runtime symbol probe
 * have to agree before anything is hooked. */
#define UKV_FOLIO_ERA	(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0))

/*
 * In native mode this is our own ceiling.  In hijack mode it is ALSO pushed into the built-in
 * driver, because the count check for UDMABUF_CREATE_LIST lives in the built-in udmabuf_ioctl()
 * -- before the udmabuf_create() we redirect -- so raising only this parameter has no effect on
 * a hijacked kernel.  That asymmetry cost an afternoon: the module's limit read 8192 while lists
 * were still being rejected at 1024 by a variable nothing pointed at.
 *
 * The ceiling matters for guest-allocated buffers, where one BO arrives as a list of drm_buddy
 * blocks: 128 MiB of 64 KiB blocks is 2048 items, over the upstream default of 1024.
 *
 * The ceiling is not this number -- it is the built-in ioctl's memdup_user() of the item array,
 * which runs before our replacement is entered and uses kmalloc. Items are 24 bytes, so 16384 of
 * them is a 384 KiB (order-7) allocation: larger than the order-6 failure this module exists to
 * fix. That is reachable only by a caller that actually sends that many items, which our guest
 * cannot -- virtio_gpu's guest_pool_max_nents caps it at 1024 -- so the headroom is for other
 * callers and costs nothing until one appears. Going higher, or making it usable, means hooking
 * the ioctl itself so the copy is ours to make with kvmalloc.
 */
static int list_limit = 16384;
module_param(list_limit, int, 0644);
MODULE_PARM_DESC(list_limit,
	"udmabuf_create_list->count limit. Applied to the built-in driver too in hijack mode. Default 16384.");

static int size_limit_mb = 4096;
module_param(size_limit_mb, int, 0644);
MODULE_PARM_DESC(size_limit_mb, "Max size of a dmabuf, in megabytes. Default 4096.");

static char *force_mode = "auto";
module_param(force_mode, charp, 0444);
MODULE_PARM_DESC(force_mode,
	"Override mode selection: auto (default), native, hijack or noop.");

/* Settled mode, readable at /sys/module/<name>/parameters/mode. */
static char mode[8] = "unset";
module_param_string(mode, mode, sizeof(mode), 0444);
MODULE_PARM_DESC(mode, "Mode this module settled on: native, hijack or noop (read-only).");

static int stat_created;
module_param(stat_created, int, 0444);
MODULE_PARM_DESC(stat_created, "dma-bufs this module has exported (read-only).");

static int stat_failed;
module_param(stat_failed, int, 0444);
MODULE_PARM_DESC(stat_failed, "create attempts this module rejected (read-only).");

/* ------------------------------------------------------------------------- */
/* Runtime symbols (none of these are guaranteed by the GKI module KMI)       */
/* ------------------------------------------------------------------------- */

static unsigned long (*ukv_lookup_name)(const char *name);
static long (*ukv_memfd_fcntl)(struct file *file, unsigned int cmd, unsigned int arg);
static int (*ukv_lookup_size_offset)(unsigned long addr, unsigned long *symbolsize,
				     unsigned long *offset);

/* kallsyms_lookup_name has not been exported since 5.7; a kprobe on it yields
 * its address without needing the export. */
static void ukv_resolve_lookup_name(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

	if (register_kprobe(&kp) < 0) {
		pr_info("kallsyms_lookup_name is not probeable; detection limited\n");
		return;
	}
	ukv_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
}

/** ukv_sym - address of a kernel symbol, or 0 when it does not exist here. */
static unsigned long ukv_sym(const char *name)
{
	return ukv_lookup_name ? ukv_lookup_name(name) : 0;
}

static void ukv_resolve_optional(void)
{
	/* Seals: upstream reads them with memfd_fcntl(), which modules cannot
	 * link against.  SHMEM_I()->seals is the fallback, so a miss here only
	 * costs us the layout-independent path, not the check. */
	ukv_memfd_fcntl = (void *)ukv_sym("memfd_fcntl");
	ukv_lookup_size_offset = (void *)ukv_sym("kallsyms_lookup_size_offset");
}

/* ------------------------------------------------------------------------- */
/* The driver (shared by native and hijack mode)                             */
/* ------------------------------------------------------------------------- */

struct udmabuf_kv {
	pgoff_t pagecount;
	struct page **pages;
	struct sg_table *sg;
	struct miscdevice *device;
};

static vm_fault_t ukv_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct udmabuf_kv *ubuf = vma->vm_private_data;
	pgoff_t pgoff = vmf->pgoff;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	unsigned long pfn;
#endif

	if (pgoff >= ubuf->pagecount)
		return VM_FAULT_SIGBUS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	pfn = page_to_pfn(ubuf->pages[pgoff]);
	return vmf_insert_pfn(vma, vmf->address, pfn);
#else
	vmf->page = ubuf->pages[pgoff];
	get_page(vmf->page);
	return 0;
#endif
}

static const struct vm_operations_struct ukv_vm_ops = {
	.fault = ukv_vm_fault,
};

static int ukv_mmap(struct dma_buf *buf, struct vm_area_struct *vma)
{
	struct udmabuf_kv *ubuf = buf->priv;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
		return -EINVAL;

	vma->vm_ops = &ukv_vm_ops;
	vma->vm_private_data = ubuf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
#endif
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int ukv_vmap(struct dma_buf *buf, struct iosys_map *map)
{
	struct udmabuf_kv *ubuf = buf->priv;
	void *vaddr;

	dma_resv_assert_held(buf->resv);
	vaddr = vm_map_ram(ubuf->pages, ubuf->pagecount, -1);
	if (!vaddr)
		return -EINVAL;

	iosys_map_set_vaddr(map, vaddr);
	return 0;
}

static void ukv_vunmap(struct dma_buf *buf, struct iosys_map *map)
{
	struct udmabuf_kv *ubuf = buf->priv;

	dma_resv_assert_held(buf->resv);
	vm_unmap_ram(map->vaddr, ubuf->pagecount);
}
#endif

static struct sg_table *ukv_get_sg_table(struct device *dev, struct dma_buf *buf,
					 enum dma_data_direction direction)
{
	struct udmabuf_kv *ubuf = buf->priv;
	struct sg_table *sg;
	int ret;

	sg = kzalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg)
		return ERR_PTR(-ENOMEM);
	ret = sg_alloc_table_from_pages(sg, ubuf->pages, ubuf->pagecount,
					0, ubuf->pagecount << PAGE_SHIFT,
					GFP_KERNEL);
	if (ret < 0)
		goto err;
	ret = dma_map_sgtable(dev, sg, direction, 0);
	if (ret < 0)
		goto err;
	return sg;

err:
	sg_free_table(sg);
	kfree(sg);
	return ERR_PTR(ret);
}

static void ukv_put_sg_table(struct device *dev, struct sg_table *sg,
			     enum dma_data_direction direction)
{
	dma_unmap_sgtable(dev, sg, direction, 0);
	sg_free_table(sg);
	kfree(sg);
}

static struct sg_table *ukv_map(struct dma_buf_attachment *at,
				enum dma_data_direction direction)
{
	return ukv_get_sg_table(at->dev, at->dmabuf, direction);
}

static void ukv_unmap(struct dma_buf_attachment *at, struct sg_table *sg,
		      enum dma_data_direction direction)
{
	return ukv_put_sg_table(at->dev, sg, direction);
}

static void ukv_release(struct dma_buf *buf)
{
	struct udmabuf_kv *ubuf = buf->priv;
	struct device *dev = ubuf->device->this_device;
	pgoff_t pg;

	if (ubuf->sg)
		ukv_put_sg_table(dev, ubuf->sg, DMA_BIDIRECTIONAL);

	for (pg = 0; pg < ubuf->pagecount; pg++)
		put_page(ubuf->pages[pg]);
	kvfree(ubuf->pages);
	kfree(ubuf);
}

static int ukv_begin_cpu(struct dma_buf *buf, enum dma_data_direction direction)
{
	struct udmabuf_kv *ubuf = buf->priv;
	struct device *dev = ubuf->device->this_device;
	int ret = 0;

	if (!ubuf->sg) {
		ubuf->sg = ukv_get_sg_table(dev, buf, direction);
		if (IS_ERR(ubuf->sg)) {
			ret = PTR_ERR(ubuf->sg);
			ubuf->sg = NULL;
		}
	} else {
		dma_sync_sgtable_for_cpu(dev, ubuf->sg, direction);
	}

	return ret;
}

static int ukv_end_cpu(struct dma_buf *buf, enum dma_data_direction direction)
{
	struct udmabuf_kv *ubuf = buf->priv;
	struct device *dev = ubuf->device->this_device;

	if (!ubuf->sg)
		return -EINVAL;

	dma_sync_sgtable_for_device(dev, ubuf->sg, direction);
	return 0;
}

static const struct dma_buf_ops ukv_dma_buf_ops = {
	.cache_sgt_mapping = true,
	.map_dma_buf	   = ukv_map,
	.unmap_dma_buf	   = ukv_unmap,
	.release	   = ukv_release,
	.mmap		   = ukv_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	.vmap		   = ukv_vmap,
	.vunmap		   = ukv_vunmap,
#endif
	.begin_cpu_access  = ukv_begin_cpu,
	.end_cpu_access    = ukv_end_cpu,
};

#define SEALS_WANTED (F_SEAL_SHRINK)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define SEALS_DENIED (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)
#else
#define SEALS_DENIED (F_SEAL_WRITE)
#endif

/**
 * ukv_is_memfd - is this file a tmpfs/shmem memfd we can take pages from?
 *
 * Not shmem_mapping(): since 6.4 that is a header inline comparing a_ops
 * against shmem_aops, and GKI's KMI trim drops shmem_aops on real devices
 * (insmod dies with "Unknown symbol shmem_aops") even though it is
 * EXPORT_SYMBOL in-tree.  Every memfd lives on the internal tmpfs mount, so the
 * superblock magic answers the same question with no symbol at all - and it
 * rejects hugetlbfs memfds, which we do not support.
 */
static bool ukv_is_memfd(struct file *file)
{
	struct inode *inode = file_inode(file);

	return S_ISREG(inode->i_mode) && inode->i_sb->s_magic == TMPFS_MAGIC;
}

/** ukv_seals - F_GET_SEALS for a file already known to be a shmem memfd. */
static long ukv_seals(struct file *memfd)
{
	if (ukv_memfd_fcntl)
		return ukv_memfd_fcntl(memfd, F_GET_SEALS, 0);
	/* memfd_fcntl is unavailable: read the seals out of the shmem inode
	 * directly.  ukv_is_memfd() has already established this is one. */
	return SHMEM_I(file_inode(memfd))->seals;
}

/**
 * ukv_create - build a dma-buf from a list of memfd ranges.
 * @device: miscdevice whose this_device is the DMA device for the sg table.
 *          Ours in native mode, the built-in driver's in hijack mode - both
 *          only ever used as a DMA device, never for its private data.
 *
 * Returns a new fd, or a negative errno.  Same contract as the in-tree
 * udmabuf_create(), which is what lets the hijack jump straight here.
 */
static long ukv_create(struct miscdevice *device,
		       struct udmabuf_create_list *head,
		       struct udmabuf_create_item *list)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct file *memfd = NULL;
	struct address_space *mapping = NULL;
	struct udmabuf_kv *ubuf;
	struct dma_buf *buf;
	pgoff_t pgoff, pgcnt, pgidx, pgbuf = 0;
	struct page *page;
	u64 pglimit;
	long seals, ret = -EINVAL;
	u32 i, flags;

	ubuf = kzalloc(sizeof(*ubuf), GFP_KERNEL);
	if (!ubuf) {
		stat_failed++;
		return -ENOMEM;
	}

	pglimit = ((u64)READ_ONCE(size_limit_mb) * 1024 * 1024) >> PAGE_SHIFT;
	for (i = 0; i < head->count; i++) {
		pgoff_t pages = list[i].size >> PAGE_SHIFT;
		pgoff_t total;

		if (!IS_ALIGNED(list[i].offset, PAGE_SIZE))
			goto err;
		if (!IS_ALIGNED(list[i].size, PAGE_SIZE))
			goto err;
		if (check_add_overflow(ubuf->pagecount, pages, &total))
			goto err;
		ubuf->pagecount = total;
		if (ubuf->pagecount > pglimit)
			goto err;
	}

	if (!ubuf->pagecount)
		goto err;

	/* The whole point of this module: kvmalloc, not kmalloc_array.  A
	 * 128 MiB buffer needs 32768 pointers = a 256 KiB (order-6) contiguous
	 * allocation, which fails on a fragmented phone; vmalloc has no such
	 * requirement. */
	ubuf->pages = kvmalloc_array(ubuf->pagecount, sizeof(*ubuf->pages),
				     GFP_KERNEL);
	if (!ubuf->pages) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < head->count; i++) {
		ret = -EBADFD;
		memfd = fget(list[i].memfd);
		if (!memfd)
			goto err;
		if (!ukv_is_memfd(memfd))
			goto err;
		mapping = memfd->f_mapping;

		seals = ukv_seals(memfd);
		if (seals == -EINVAL)
			goto err;
		ret = -EINVAL;
		if ((seals & SEALS_WANTED) != SEALS_WANTED ||
		    (seals & SEALS_DENIED) != 0)
			goto err;

		pgoff = list[i].offset >> PAGE_SHIFT;
		pgcnt = list[i].size   >> PAGE_SHIFT;
		for (pgidx = 0; pgidx < pgcnt; pgidx++) {
			page = shmem_read_mapping_page(mapping, pgoff + pgidx);
			if (IS_ERR(page)) {
				ret = PTR_ERR(page);
				goto err;
			}
			ubuf->pages[pgbuf++] = page;
		}
		fput(memfd);
		memfd = NULL;
	}

	exp_info.ops  = &ukv_dma_buf_ops;
	exp_info.size = ubuf->pagecount << PAGE_SHIFT;
	exp_info.priv = ubuf;
	exp_info.flags = O_RDWR;

	ubuf->device = device;
	/* DEFINE_DMA_BUF_EXPORT_INFO set exp_info.owner = THIS_MODULE, so every
	 * live buffer holds a reference on us: rmmod is -EBUSY until userspace
	 * closes them, and our ops can never outlive the module. */
	buf = dma_buf_export(&exp_info);
	if (IS_ERR(buf)) {
		ret = PTR_ERR(buf);
		goto err;
	}

	flags = 0;
	if (head->flags & UDMABUF_FLAGS_CLOEXEC)
		flags |= O_CLOEXEC;
	ret = dma_buf_fd(buf, flags);
	if (ret < 0) {
		dma_buf_put(buf);
		stat_failed++;
		return ret;
	}
	stat_created++;
	return ret;

err:
	while (pgbuf > 0)
		put_page(ubuf->pages[--pgbuf]);
	if (memfd)
		fput(memfd);
	kvfree(ubuf->pages);
	kfree(ubuf);
	stat_failed++;
	return ret;
}

/* ------------------------------------------------------------------------- */
/* Native mode: our own /dev/udmabuf                                         */
/* ------------------------------------------------------------------------- */

static long ukv_ioctl_create(struct file *filp, unsigned long arg)
{
	struct udmabuf_create create;
	struct udmabuf_create_list head;
	struct udmabuf_create_item list;

	if (copy_from_user(&create, (void __user *)arg, sizeof(create)))
		return -EFAULT;

	head.flags  = create.flags;
	head.count  = 1;
	list.memfd  = create.memfd;
	list.offset = create.offset;
	list.size   = create.size;

	return ukv_create(filp->private_data, &head, &list);
}

static long ukv_ioctl_create_list(struct file *filp, unsigned long arg)
{
	struct udmabuf_create_list head;
	struct udmabuf_create_item *list;
	int ret = -EINVAL;
	u32 lsize;

	if (copy_from_user(&head, (void __user *)arg, sizeof(head)))
		return -EFAULT;
	if (head.count > list_limit)
		return -EINVAL;
	lsize = sizeof(struct udmabuf_create_item) * head.count;
	list = memdup_user((void __user *)(arg + sizeof(head)), lsize);
	if (IS_ERR(list))
		return PTR_ERR(list);

	ret = ukv_create(filp->private_data, &head, list);
	kfree(list);
	return ret;
}

static long ukv_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	switch (ioctl) {
	case UDMABUF_CREATE:
		return ukv_ioctl_create(filp, arg);
	case UDMABUF_CREATE_LIST:
		return ukv_ioctl_create_list(filp, arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ukv_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = ukv_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = ukv_ioctl,
#endif
};

static struct miscdevice ukv_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "udmabuf",
	.fops	= &ukv_fops,
};

static bool ukv_misc_registered;

static int ukv_native_start(void)
{
	int ret;

	ret = misc_register(&ukv_misc);
	if (ret < 0)
		return ret;

	/* DMA_BIT_MASK(64) trips clang's -Wshift-count-overflow in external
	 * module builds; ~0ULL is what it expands to for 64 bits. */
	ret = dma_coerce_mask_and_coherent(ukv_misc.this_device, ~0ULL);
	if (ret < 0) {
		misc_deregister(&ukv_misc);
		return ret;
	}

	ukv_misc_registered = true;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Hijack mode: redirect the built-in udmabuf_create() to ours               */
/* ------------------------------------------------------------------------- */

/*
 * Entered with x0..x2 already holding the built-in udmabuf_create()'s three
 * arguments (the kprobe fires at its first instruction, before the prologue
 * touches them), so the replacement just runs as if it had been called.
 */
static long ukv_create_hijacked(struct miscdevice *device,
				struct udmabuf_create_list *head,
				struct udmabuf_create_item *list)
{
	long ret = ukv_create(device, head, list);

	/* Paired with try_module_get() in ukv_pre_create(): it kept us loaded
	 * across this call, which no dma_buf reference covers on the error
	 * paths. */
	module_put(THIS_MODULE);
	return ret;
}

static int ukv_pre_create(struct kprobe *p, struct pt_regs *regs)
{
	/* Fails only while the module is being unloaded; then we leave the PC
	 * alone and the built-in implementation runs, which is always safe. */
	if (!try_module_get(THIS_MODULE))
		return 0;

	instruction_pointer_set(regs, (unsigned long)ukv_create_hijacked);
	return 1;	/* do not execute the probed instruction */
}

static struct kprobe ukv_kp_create = {
	.symbol_name = "udmabuf_create",
	.pre_handler = ukv_pre_create,
};

static bool ukv_hooked;

/*
 * The built-in driver's own list_limit, and what it held before we touched it.
 *
 * Hijacking udmabuf_create() does not reach the UDMABUF_CREATE_LIST count check: on this
 * kernel that check is inlined into udmabuf_ioctl(), which runs first and rejects the call
 * before our replacement is entered.  Rather than hook a second, much larger function, raise
 * the variable it reads.  `list_limit` resolves uniquely in kallsyms on every kernel this
 * module targets, so the lookup is not ambiguous.
 *
 * Restored on unload: leaving another driver's tunable moved after rmmod would be a change
 * nothing accounts for, and the next thing to hit the old value would have no way to explain it.
 */
static int *ukv_builtin_list_limit;
static int ukv_builtin_list_limit_saved;

static void ukv_raise_builtin_list_limit(void)
{
	int want = READ_ONCE(list_limit);
	int *p = (int *)ukv_sym("list_limit");

	if (!p) {
		pr_info("built-in list_limit not in kallsyms; UDMABUF_CREATE_LIST stays capped at its default\n");
		return;
	}
	if (*p >= want) {
		pr_info("built-in list_limit already %d (>= %d), left alone\n", *p, want);
		return;
	}

	ukv_builtin_list_limit = p;
	ukv_builtin_list_limit_saved = *p;
	WRITE_ONCE(*p, want);
	pr_info("built-in list_limit %d -> %d\n", ukv_builtin_list_limit_saved, want);
}

static void ukv_restore_builtin_list_limit(void)
{
	if (!ukv_builtin_list_limit)
		return;
	WRITE_ONCE(*ukv_builtin_list_limit, ukv_builtin_list_limit_saved);
	pr_info("built-in list_limit restored to %d\n", ukv_builtin_list_limit_saved);
	ukv_builtin_list_limit = NULL;
}

/**
 * ukv_bl_target - absolute target of an arm64 "BL imm26", or 0 if not a BL.
 *
 * imm26 is a signed word offset; shifting it up to the sign bit and back down
 * arithmetically sign-extends it and multiplies by 4 in one step.
 */
static unsigned long ukv_bl_target(const u32 *at)
{
	u32 insn = READ_ONCE(*at);

	if ((insn & 0xfc000000) != 0x94000000)
		return 0;
	return (unsigned long)at + (((s32)(insn << 6)) >> 4);
}

/** ukv_calls - does the function at @fn contain a direct call to @target? */
static bool ukv_calls(unsigned long fn, unsigned long len, unsigned long target)
{
	const u32 *insn = (const u32 *)fn;
	unsigned long i;

	if (!fn || !len || !target)
		return false;
	for (i = 0; i < len / sizeof(*insn); i++)
		if (ukv_bl_target(&insn[i]) == target)
			return true;
	return false;
}

/** ukv_first_call - name of the first symbol in @names that @fn calls. */
static const char *ukv_first_call(unsigned long fn, unsigned long len,
				  const char * const *names)
{
	int i;

	for (i = 0; names[i]; i++)
		if (ukv_calls(fn, len, ukv_sym(names[i])))
			return names[i];
	return NULL;
}

/**
 * ukv_builtin_is_fixed - does the built-in udmabuf_create() already kvmalloc?
 *
 * The fix is one call site swapped from kmalloc_array() to kvmalloc_array(),
 * and kvmalloc_array() is an inline that always ends in a call to
 * kvmalloc_node(), so its presence in the function's own code is the test.
 * Inconclusive answers (no symbol, no size) report "not fixed": hooking a
 * kernel that turned out to be fixed costs nothing - the replacement does the
 * same work - while skipping a kernel that is broken costs the user the bug.
 *
 * The unfixed kernel's own allocator call is looked up too, purely so the
 * log line carries the evidence for the verdict: seeing "calls __kmalloc"
 * proves the scan can find a call at all, which is what makes its silence
 * about kvmalloc_node worth trusting.
 */
static bool ukv_builtin_is_fixed(unsigned long create)
{
	static const char * const kvmalloc[] = {
		"kvmalloc_node", "kvmalloc_node_noprof", NULL,
	};
	static const char * const kmalloc[] = {
		"__kmalloc", "__kmalloc_node", "__kmalloc_noprof",
		"__kmalloc_node_noprof", "kmalloc_trace", NULL,
	};
	unsigned long size = 0, off = 0;
	const char *hit;

	if (!ukv_lookup_size_offset || !create) {
		pr_info("cannot read udmabuf_create's extent; assuming unfixed\n");
		return false;
	}
	if (!ukv_lookup_size_offset(create, &size, &off) || !size || off) {
		pr_info("udmabuf_create has no usable size in kallsyms; assuming unfixed\n");
		return false;
	}

	hit = ukv_first_call(create, size, kvmalloc);
	if (hit) {
		pr_info("built-in udmabuf_create (%lu bytes) calls %s\n", size, hit);
		return true;
	}

	hit = ukv_first_call(create, size, kmalloc);
	pr_info("built-in udmabuf_create (%lu bytes) calls %s, no kvmalloc\n",
		size, hit ? hit : "no allocator this scan knows");
	return false;
}

/* ------------------------------------------------------------------------- */
/* Mode selection                                                            */
/* ------------------------------------------------------------------------- */

enum ukv_mode { UKV_NOOP, UKV_NATIVE, UKV_HIJACK };

static void ukv_set_mode(enum ukv_mode m)
{
	strscpy(mode, m == UKV_NATIVE ? "native" :
		      m == UKV_HIJACK ? "hijack" : "noop", sizeof(mode));
}

/**
 * ukv_pick_mode - decide what this kernel needs.
 *
 * Anything unexpected lands on noop: this module exists to add a capability or
 * repair one, never to take a working /dev/udmabuf away from the system.
 */
static enum ukv_mode ukv_pick_mode(void)
{
	unsigned long create;

	/* The built-in driver's own static symbols.  Ours are all ukv_*, so
	 * these can only ever match the kernel's (or a loaded udmabuf.ko's). */
	create = ukv_sym("udmabuf_create");
	if (!create && !ukv_sym("udmabuf_ops")) {
		/* No provider we can see.  If one exists anyway (kallsyms is
		 * unavailable, say), misc_register will tell us by failing. */
		pr_info("no built-in udmabuf found\n");
		return UKV_NATIVE;
	}

	if (UKV_FOLIO_ERA || ukv_sym("memfd_pin_folios")) {
		pr_info("built-in udmabuf is the folio-based driver (>= 6.10), which carries the fix\n");
		return UKV_NOOP;
	}

	if (!create) {
		pr_info("built-in udmabuf present but udmabuf_create is not in kallsyms; cannot hook\n");
		return UKV_NOOP;
	}

	if (ukv_builtin_is_fixed(create)) {
		pr_info("built-in udmabuf already allocates with kvmalloc; nothing to do\n");
		return UKV_NOOP;
	}

	pr_info("built-in udmabuf allocates its page array with kmalloc (unfixed)\n");
	return UKV_HIJACK;
}

static int __init ukv_init(void)
{
	enum ukv_mode m;
	bool forced = true;
	int ret;

	ukv_resolve_lookup_name();
	ukv_resolve_optional();

	if (!strcmp(force_mode, "native"))
		m = UKV_NATIVE;
	else if (!strcmp(force_mode, "hijack"))
		m = UKV_HIJACK;
	else if (!strcmp(force_mode, "noop"))
		m = UKV_NOOP;
	else {
		if (strcmp(force_mode, "auto"))
			pr_warn("unknown force_mode \"%s\", using auto\n", force_mode);
		m = ukv_pick_mode();
		forced = false;
	}

	switch (m) {
	case UKV_NATIVE:
		ret = ukv_native_start();
		if (ret == -EEXIST) {
			/* Someone owns /dev/udmabuf after all. */
			pr_info("/dev/udmabuf already exists; standing down\n");
			m = UKV_NOOP;
			break;
		}
		if (ret < 0) {
			pr_err("could not register /dev/udmabuf: %d\n", ret);
			return ret;
		}
		pr_info("mode=native: /dev/udmabuf registered, size_limit_mb=%d\n",
			READ_ONCE(size_limit_mb));
		break;
	case UKV_HIJACK:
		ret = register_kprobe(&ukv_kp_create);
		if (ret < 0) {
			pr_err("could not hook udmabuf_create: %d\n", ret);
			if (forced)
				return ret;
			m = UKV_NOOP;
			break;
		}
		ukv_hooked = true;
		ukv_raise_builtin_list_limit();
		pr_info("mode=hijack: udmabuf_create redirected, size_limit_mb=%d list_limit=%d\n",
			READ_ONCE(size_limit_mb), READ_ONCE(list_limit));
		break;
	case UKV_NOOP:
		pr_info("mode=noop: this kernel needs nothing from us\n");
		break;
	}

	ukv_set_mode(m);
	return 0;
}

static void __exit ukv_exit(void)
{
	if (ukv_hooked) {
		unregister_kprobe(&ukv_kp_create);
		ukv_restore_builtin_list_limit();
	}
	if (ukv_misc_registered)
		misc_deregister(&ukv_misc);
	pr_info("removed (mode=%s, created=%d)\n", mode, stat_created);
}

module_init(ukv_init);
module_exit(ukv_exit);

MODULE_AUTHOR("Gerd Hoffmann <kraxel@redhat.com>");
MODULE_DESCRIPTION("udmabuf provider/kvmalloc repair for hosts whose kernel lacks either");
MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(DMA_BUF);
