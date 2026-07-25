// SPDX-License-Identifier: GPL-2.0
/*
 * Out-of-tree copy of the upstream udmabuf driver (drivers/dma-buf/udmabuf.c)
 * for host kernels shipped with CONFIG_UDMABUF unset -- every GKI gki_defconfig
 * since 6.1 enables it, but vendor kernel_platform builds (e.g. QCOM 6.1) may
 * not. gfxstream's host-visible blob path imports blob memfds as dma-bufs
 * through /dev/udmabuf, so those hosts need this module.
 *
 * One source builds unchanged for GKI 6.1 / 6.6 / 6.12. Differences from the
 * in-tree driver:
 *  - init no-ops when /dev/udmabuf already exists (misc_register -EEXIST from
 *    the in-tree driver's device): the module stays loaded but registers
 *    nothing, so it is always safe to autostart on every KMI.
 *  - hugetlb memfds are rejected outright: memfd_fcntl() is not exported to
 *    modules, so seals are read via SHMEM_I() and only shmem memfds can be
 *    checked. This also drops the hugetlb header/API surface, which is what
 *    varies most across 6.1..6.12.
 *  - size_limit_mb defaults to 4096 (not 64) and the pglimit arithmetic is
 *    done in u64: upstream's int math overflows for size_limit_mb >= 4096
 *    (e.g. 16384 -> 2^34 truncates to 0, rejecting everything).
 */
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/udmabuf.h>

static int list_limit = 1024;
module_param(list_limit, int, 0644);
MODULE_PARM_DESC(list_limit, "udmabuf_create_list->count limit. Default is 1024.");

static int size_limit_mb = 4096;
module_param(size_limit_mb, int, 0644);
MODULE_PARM_DESC(size_limit_mb, "Max size of a dmabuf, in megabytes. Default is 4096.");

struct udmabuf {
	pgoff_t pagecount;
	struct page **pages;
	struct sg_table *sg;
	struct miscdevice *device;
};

static vm_fault_t udmabuf_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct udmabuf *ubuf = vma->vm_private_data;
	pgoff_t pgoff = vmf->pgoff;

	if (pgoff >= ubuf->pagecount)
		return VM_FAULT_SIGBUS;
	vmf->page = ubuf->pages[pgoff];
	get_page(vmf->page);
	return 0;
}

static const struct vm_operations_struct udmabuf_vm_ops = {
	.fault = udmabuf_vm_fault,
};

static int mmap_udmabuf(struct dma_buf *buf, struct vm_area_struct *vma)
{
	struct udmabuf *ubuf = buf->priv;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
		return -EINVAL;

	vma->vm_ops = &udmabuf_vm_ops;
	vma->vm_private_data = ubuf;
	return 0;
}

static struct sg_table *get_sg_table(struct device *dev, struct dma_buf *buf,
				     enum dma_data_direction direction)
{
	struct udmabuf *ubuf = buf->priv;
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

static void put_sg_table(struct device *dev, struct sg_table *sg,
			 enum dma_data_direction direction)
{
	dma_unmap_sgtable(dev, sg, direction, 0);
	sg_free_table(sg);
	kfree(sg);
}

static struct sg_table *map_udmabuf(struct dma_buf_attachment *at,
				    enum dma_data_direction direction)
{
	return get_sg_table(at->dev, at->dmabuf, direction);
}

static void unmap_udmabuf(struct dma_buf_attachment *at,
			  struct sg_table *sg,
			  enum dma_data_direction direction)
{
	return put_sg_table(at->dev, sg, direction);
}

static void release_udmabuf(struct dma_buf *buf)
{
	struct udmabuf *ubuf = buf->priv;
	struct device *dev = ubuf->device->this_device;
	pgoff_t pg;

	if (ubuf->sg)
		put_sg_table(dev, ubuf->sg, DMA_BIDIRECTIONAL);

	for (pg = 0; pg < ubuf->pagecount; pg++)
		put_page(ubuf->pages[pg]);
	kfree(ubuf->pages);
	kfree(ubuf);
}

static int begin_cpu_udmabuf(struct dma_buf *buf,
			     enum dma_data_direction direction)
{
	struct udmabuf *ubuf = buf->priv;
	struct device *dev = ubuf->device->this_device;
	int ret = 0;

	if (!ubuf->sg) {
		ubuf->sg = get_sg_table(dev, buf, direction);
		if (IS_ERR(ubuf->sg)) {
			ret = PTR_ERR(ubuf->sg);
			ubuf->sg = NULL;
		}
	} else {
		dma_sync_sg_for_cpu(dev, ubuf->sg->sgl, ubuf->sg->nents,
				    direction);
	}

	return ret;
}

static int end_cpu_udmabuf(struct dma_buf *buf,
			   enum dma_data_direction direction)
{
	struct udmabuf *ubuf = buf->priv;
	struct device *dev = ubuf->device->this_device;

	if (!ubuf->sg)
		return -EINVAL;

	dma_sync_sg_for_device(dev, ubuf->sg->sgl, ubuf->sg->nents, direction);
	return 0;
}

static const struct dma_buf_ops udmabuf_ops = {
	.cache_sgt_mapping = true,
	.map_dma_buf	   = map_udmabuf,
	.unmap_dma_buf	   = unmap_udmabuf,
	.release	   = release_udmabuf,
	.mmap		   = mmap_udmabuf,
	.begin_cpu_access  = begin_cpu_udmabuf,
	.end_cpu_access    = end_cpu_udmabuf,
};

#define SEALS_WANTED (F_SEAL_SHRINK)
#define SEALS_DENIED (F_SEAL_WRITE)

static long udmabuf_create(struct miscdevice *device,
			   struct udmabuf_create_list *head,
			   struct udmabuf_create_item *list)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct file *memfd = NULL;
	struct address_space *mapping = NULL;
	struct udmabuf *ubuf;
	struct dma_buf *buf;
	pgoff_t pgoff, pgcnt, pgidx, pgbuf = 0, pglimit;
	struct page *page;
	int seals, ret = -EINVAL;
	u32 i, flags;

	ubuf = kzalloc(sizeof(*ubuf), GFP_KERNEL);
	if (!ubuf)
		return -ENOMEM;

	pglimit = ((u64)size_limit_mb * 1024 * 1024) >> PAGE_SHIFT;
	for (i = 0; i < head->count; i++) {
		if (!IS_ALIGNED(list[i].offset, PAGE_SIZE))
			goto err;
		if (!IS_ALIGNED(list[i].size, PAGE_SIZE))
			goto err;
		ubuf->pagecount += list[i].size >> PAGE_SHIFT;
		if (ubuf->pagecount > pglimit)
			goto err;
	}

	if (!ubuf->pagecount)
		goto err;

	ubuf->pages = kmalloc_array(ubuf->pagecount, sizeof(*ubuf->pages),
				    GFP_KERNEL);
	if (!ubuf->pages) {
		ret = -ENOMEM;
		goto err;
	}

	pgbuf = 0;
	for (i = 0; i < head->count; i++) {
		ret = -EBADFD;
		memfd = fget(list[i].memfd);
		if (!memfd)
			goto err;
		mapping = memfd->f_mapping;
		/* Not shmem_mapping(): since 6.4 that is a header inline comparing
		 * against &shmem_aops, which GKI's KMI symbol trim drops on real
		 * devices (it is in no vendor symbol list). The tmpfs superblock
		 * magic needs no export and also rejects hugetlbfs memfds. */
		if (file_inode(memfd)->i_sb->s_magic != TMPFS_MAGIC)
			goto err;
		seals = SHMEM_I(file_inode(memfd))->seals;
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

	exp_info.ops  = &udmabuf_ops;
	exp_info.size = ubuf->pagecount << PAGE_SHIFT;
	exp_info.priv = ubuf;
	exp_info.flags = O_RDWR;

	ubuf->device = device;
	buf = dma_buf_export(&exp_info);
	if (IS_ERR(buf)) {
		ret = PTR_ERR(buf);
		goto err;
	}

	flags = 0;
	if (head->flags & UDMABUF_FLAGS_CLOEXEC)
		flags |= O_CLOEXEC;
	return dma_buf_fd(buf, flags);

err:
	while (pgbuf > 0)
		put_page(ubuf->pages[--pgbuf]);
	if (memfd)
		fput(memfd);
	kfree(ubuf->pages);
	kfree(ubuf);
	return ret;
}

static long udmabuf_ioctl_create(struct file *filp, unsigned long arg)
{
	struct udmabuf_create create;
	struct udmabuf_create_list head;
	struct udmabuf_create_item list;

	if (copy_from_user(&create, (void __user *)arg,
			   sizeof(create)))
		return -EFAULT;

	head.flags  = create.flags;
	head.count  = 1;
	list.memfd  = create.memfd;
	list.offset = create.offset;
	list.size   = create.size;

	return udmabuf_create(filp->private_data, &head, &list);
}

static long udmabuf_ioctl_create_list(struct file *filp, unsigned long arg)
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

	ret = udmabuf_create(filp->private_data, &head, list);
	kfree(list);
	return ret;
}

static long udmabuf_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	long ret;

	switch (ioctl) {
	case UDMABUF_CREATE:
		ret = udmabuf_ioctl_create(filp, arg);
		break;
	case UDMABUF_CREATE_LIST:
		ret = udmabuf_ioctl_create_list(filp, arg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}
	return ret;
}

static const struct file_operations udmabuf_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = udmabuf_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = udmabuf_ioctl,
#endif
};

static struct miscdevice udmabuf_misc = {
	.minor          = MISC_DYNAMIC_MINOR,
	.name           = "udmabuf",
	.fops           = &udmabuf_fops,
};

/* False when init stood down because the in-tree driver owns /dev/udmabuf. */
static bool udmabuf_registered;

static int __init udmabuf_dev_init(void)
{
	int ret;

	ret = misc_register(&udmabuf_misc);
	if (ret == -EEXIST) {
		pr_info("udmabuf: /dev/udmabuf already provided by the kernel, standing down\n");
		return 0;
	}
	if (ret < 0) {
		pr_err("Could not initialize udmabuf device\n");
		return ret;
	}

	/* DMA_BIT_MASK(64) trips clang's -Wshift-count-overflow in external
	 * module builds; ~0ULL is what it expands to for 64 bits. */
	ret = dma_coerce_mask_and_coherent(udmabuf_misc.this_device, ~0ULL);
	if (ret < 0) {
		pr_err("Could not setup DMA mask for udmabuf device\n");
		misc_deregister(&udmabuf_misc);
		return ret;
	}

	udmabuf_registered = true;
	return 0;
}

static void __exit udmabuf_dev_exit(void)
{
	if (udmabuf_registered)
		misc_deregister(&udmabuf_misc);
}

module_init(udmabuf_dev_init)
module_exit(udmabuf_dev_exit)

MODULE_AUTHOR("Gerd Hoffmann <kraxel@redhat.com>");
MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(DMA_BUF);
