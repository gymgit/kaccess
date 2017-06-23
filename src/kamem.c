#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/raw.h>
//#include <linux/tty.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
#include <linux/splice.h>
#include <linux/pfn.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/uio.h>

#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/io.h> //for debug purposes
#include "kaccess.h"
//#include "kamem.h"
long (*vread_p)(char *, char*, unsigned long)=NULL;
long (*vwrite_p)(char*, char*, unsigned long)=NULL;

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;

	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE

static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}

static inline int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return 1;
}
#endif
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	return 1;
}

int __weak phys_mem_access_prot_allowed(struct file *file,
	unsigned long pfn, unsigned long size, pgprot_t *vma_prot)
{
	return 1;
}

//#ifndef __HAVE_PHYS_MEM_ACCESS_PROT

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
#ifdef pgprot_noncached
static int uncached_access2(struct file *file, phys_addr_t addr)
{
	/*
	 * Accessing memory above the top the kernel knows about or through a
	 * file pointer
	 * that was marked O_DSYNC will be done non-cached.
	 */
	if (file->f_flags & O_DSYNC)
		return 1;
	return addr >= __pa(high_memory);
}
#endif

static pgprot_t phys_mem_access_prot2(struct file *file, unsigned long pfn,
				     unsigned long size, pgprot_t vma_prot)
{
#ifdef pgprot_noncached
	phys_addr_t offset = pfn << PAGE_SHIFT;

	if (uncached_access2(file, offset))
		return pgprot_noncached(vma_prot);
#endif
	return vma_prot;
}
//#endif

#ifndef CONFIG_MMU
static unsigned long get_unmapped_area_mem(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	return pgoff << PAGE_SHIFT;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_MAYSHARE;
}
#else
#define get_unmapped_area_mem	NULL

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return 1;
}
#endif

static const struct vm_operations_struct mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys
#endif
};

static int mmap_mem(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;


	if (!private_mapping_ok(vma))
		return -ENOSYS;

	if (!range_is_allowed(vma->vm_pgoff, size))
		return -EPERM;

	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
						&vma->vm_page_prot))
		return -EINVAL;

	vma->vm_page_prot = phys_mem_access_prot2(file, vma->vm_pgoff,
						 size,
						 vma->vm_page_prot);

	vma->vm_ops = &mmap_mem_ops;

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}

static int mmap_kmem(struct file *file, struct vm_area_struct *vma)
{
	unsigned long pfn;

	/* Turn a kernel-virtual address into a physical page frame */
	pfn = __pa((u64)vma->vm_pgoff << PAGE_SHIFT) >> PAGE_SHIFT;

	/*
	 * RED-PEN: on some architectures there is more mapped memory than
	 * available in mem_map which pfn_valid checks for. Perhaps should add a
	 * new macro here.
	 *
	 * RED-PEN: vmalloc is not supported right now.
	 */
	if (!pfn_valid(pfn))
		return -EIO;

	vma->vm_pgoff = pfn;
	return mmap_mem(file, vma);
}

void *xlate_dev_mem_ptr(phys_addr_t phys)
{
    unsigned long start  = phys &  PAGE_MASK;
    unsigned long offset = phys & ~PAGE_MASK;
    void *vaddr;

    /* If page is RAM, we can use __va. Otherwise ioremap and unmap. */
    if (page_is_ram(start >> PAGE_SHIFT))
            return __va(phys);

    vaddr = ioremap_cache(start, PAGE_SIZE);
    /* Only add the offset on success and return NULL if the ioremap() failed: */
    if (vaddr)
            vaddr += offset;

    return vaddr;
}

void unxlate_dev_mem_ptr(phys_addr_t phys, void *addr)
{
    if (page_is_ram(phys >> PAGE_SHIFT))
            return;

    iounmap((void __iomem *)((unsigned long)addr & PAGE_MASK));
}

static ssize_t read_mem(struct file *file, char __user *buf,
                        size_t count, loff_t *ppos)
{
    phys_addr_t p = *ppos;
    ssize_t read, sz;
    void *ptr;

    printk(KERN_INFO "[ka_mem] Reading physical memory\n");
    if (p != *ppos)
            return 0;

    if (!valid_phys_addr_range(p, count))
            return -EFAULT;
    read = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
    /* we don't have page 0 mapped on sparc and m68k.. */
    if (p < PAGE_SIZE) {
            sz = size_inside_page(p, count);
            if (sz > 0) {
                    if (clear_user(buf, sz))
                            return -EFAULT;
                    buf += sz;
                    p += sz;
                    count -= sz;
                    read += sz;
            }
    }
#endif

    while (count > 0) {
            unsigned long remaining;

            sz = size_inside_page(p, count);

            if (!range_is_allowed(p >> PAGE_SHIFT, count))
                    return -EPERM;

            /*
             * On ia64 if a page has been mapped somewhere as uncached, then
             * it must also be accessed uncached by the kernel or data
             * corruption may occur.
             */
            ptr = xlate_dev_mem_ptr(p);
            if (!ptr)
                    return -EFAULT;

            remaining = copy_to_user(buf, ptr, sz);
            //printk(KERN_INFO "[ka_mem] sending data to user: %c\n", ptr[0]);
            unxlate_dev_mem_ptr(p, ptr);
            if (remaining)
                    return -EFAULT;

            buf += sz;
            p += sz;
            count -= sz;
            read += sz;
    }

    *ppos += read;
    return read;
}

static ssize_t write_mem(struct file *file, const char __user *buf,
                     size_t count, loff_t *ppos)
{
    phys_addr_t p = *ppos;
    ssize_t written, sz;
    unsigned long copied;
    void *ptr;

    printk(KERN_INFO "[ka_mem] Trying to write to physical memory at %llx\n",*ppos);
    if (p != *ppos)
            return -EFBIG;

    if (!valid_phys_addr_range(p, count))
            return -EFAULT;

    written = 0;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
    /* we don't have page 0 mapped on sparc and m68k.. */
    if (p < PAGE_SIZE) {
            sz = size_inside_page(p, count);
            /* Hmm. Do something? */
            buf += sz;
            p += sz;
            count -= sz;
            written += sz;
    }
#endif

    while (count > 0) {
            sz = size_inside_page(p, count);

            if (!range_is_allowed(p >> PAGE_SHIFT, sz))
                    return -EPERM;

            /*
             * On ia64 if a page has been mapped somewhere as uncached, then
             * it must also be accessed uncached by the kernel or data
             * corruption may occur.
             */
            ptr = xlate_dev_mem_ptr(p);
            if (!ptr) {
                    if (written)
                            break;
                    return -EFAULT;
            }

            copied = copy_from_user(ptr, buf, sz);
            //printk(KERN_INFO "[ka_mem] Writing to kernel %c %c %c %c\n", ptr[0], ptr[1], ptr[2], ptr[3]);
            unxlate_dev_mem_ptr(p, ptr);
            if (copied) {
                    written += sz - copied;
                    if (written)
                            break;
                    return -EFAULT;
            }

            buf += sz;
            p += sz;
            count -= sz;
            written += sz;
    }

    *ppos += written;
    return written;
}
/*
 * This function reads the *virtual* memory as seen by the kernel.
 */
static ssize_t read_kmem(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
    ssize_t low_count, read, sz;
	char *kbuf; /* k-addr because vread() takes vmlist_lock rwlock */
	int err = 0;

	read = 0;
    printk(KERN_INFO "[ka_kmem] Reading kernel memory\n");
	if (p < (unsigned long) high_memory) {
		low_count = count;
		if (count > (unsigned long)high_memory - p)
			low_count = (unsigned long)high_memory - p;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
		/* we don't have page 0 mapped on sparc and m68k.. */
		if (p < PAGE_SIZE && low_count > 0) {
			sz = size_inside_page(p, low_count);
			if (clear_user(buf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
		}
#endif
		while (low_count > 0) {
			sz = size_inside_page(p, low_count);

			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur
			 */
			kbuf = xlate_dev_kmem_ptr((char *)p);

            printk(KERN_INFO "[ka_kmem] sending data to user: %c\n", kbuf[0]);
			if (copy_to_user(buf, kbuf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
		}
	}

	if (count > 0) {
		kbuf = (char *)__get_free_page(GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		while (count > 0) {
			sz = size_inside_page(p, count);
            // we dont want to only be able to read vmalloc area
            // but rather the entire virtual address space
			//sz = vread_p(kbuf, (char *)p, sz);
            // we simply read from the virtual address
            // NOTE this is unsafe, but hey we are here for the crashes
            printk(KERN_INFO "[ka_kmem] reading %lu bytes\n", sz);
			if (!sz)
				break;

            printk(KERN_INFO "[ka_kmem] sending data to user: %c\n", kbuf[0]);
			if (copy_to_user(buf, (char*)p, sz)) {
				err = -EFAULT;
				break;
			}
			count -= sz;
			buf += sz;
			read += sz;
			p += sz;
		}
		free_page((unsigned long)kbuf);
	}
	*ppos = p;
	return read ? read : err;
}


static ssize_t do_write_kmem(unsigned long p, const char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t written, sz;
	unsigned long copied;

    printk(KERN_INFO "[ka_kmem] Mykmem do write\n");
	written = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = size_inside_page(p, count);
		/* Hmm. Do something? */
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}
#endif

	while (count > 0) {
		char *ptr;

		sz = size_inside_page(p, count);

		/*
		 * On ia64 if a page has been mapped somewhere as uncached, then
		 * it must also be accessed uncached by the kernel or data
		 * corruption may occur.
		 */
		ptr = xlate_dev_kmem_ptr((char *)p);

		copied = copy_from_user(ptr, buf, sz);
		if (copied) {
			written += sz - copied;
			if (written)
				break;
			return -EFAULT;
		}
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}

	*ppos += written;
	return written;
}

/*
 * This function writes to the *virtual* memory as seen by the kernel.
 */
static ssize_t write_kmem(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t wrote = 0;
	ssize_t virtr = 0;
	char *kbuf; /* k-addr because vwrite() takes vmlist_lock rwlock */
	int err = 0;

    printk(KERN_INFO "[ka_kmem] Trying to write to kernel at %llx\n",*ppos);
	if (p < (unsigned long) high_memory) {
		unsigned long to_write = min_t(unsigned long, count,
					       (unsigned long)high_memory - p);
		wrote = do_write_kmem(p, buf, to_write, ppos);
		if (wrote != to_write)
			return wrote;
		p += wrote;
		buf += wrote;
		count -= wrote;
	}

	if (count > 0) {
		kbuf = (char *)__get_free_page(GFP_KERNEL);
		if (!kbuf)
			return wrote ? wrote : -ENOMEM;
		while (count > 0) {
			unsigned long sz = size_inside_page(p, count);
			unsigned long n;

			n = copy_from_user(kbuf, buf, sz);
            printk(KERN_INFO "[ka_kmem] Writing to kernel %c %c %c %c\n", kbuf[0], kbuf[1], kbuf[2], kbuf[3]);
			if (n) {
				err = -EFAULT;
				break;
			}
			vwrite_p(kbuf, (char *)p, sz);
			count -= sz;
			buf += sz;
			virtr += sz;
			p += sz;
		}
		free_page((unsigned long)kbuf);
	}

	*ppos = p;
	return virtr + wrote ? : err;
}


/*
 * The memory devices use the full 32/64 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static loff_t memory_lseek(struct file *file, loff_t offset, int orig)
{
	loff_t ret;

    printk(KERN_INFO "[ka_kmem] lseeking to %llx\n", offset);
    printk(KERN_INFO "[ka_kmem] physical  %llx\n", virt_to_phys((void*)offset));
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,0)
	mutex_lock(&file_inode(file)->i_mutex);
#else
    inode_lock(file_inode(file));   
#endif
	switch (orig) {
	case SEEK_CUR:
		offset += file->f_pos;
	case SEEK_SET:
		/* to avoid userland mistaking f_pos=-9 as -EBADF=-9 */
		if ((unsigned long long)offset >= ~0xFFFULL) {
			ret = -EOVERFLOW;
            printk(KERN_INFO "[ka_kmem] Overflow in lseek\n");
			break;
		}
		file->f_pos = offset;
		ret = file->f_pos;
		force_successful_syscall_return();
		break;
	default:
		ret = -EINVAL;
	}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,7,0)
	mutex_unlock(&file_inode(file)->i_mutex);
#else
    inode_unlock(file_inode(file));   
#endif
    printk(KERN_INFO "[ka_kmem] seeked ret: %llx\n", ret);
	return ret;
}

static int open_kmem(struct inode *inode, struct file *filp)
{
    printk(KERN_INFO "[ka_kmem] kmem opened: %d\n", capable(CAP_SYS_RAWIO) ? 0 : -EPERM);
    printk(KERN_INFO "[ka_kmem] high mem: %lx\n", (unsigned long)high_memory);
    printk(KERN_INFO "[ka_kmem] file mode: %x\n", filp->f_mode);
    printk(KERN_INFO "[ka_kmem] playground at: %llx\n", (unsigned long long)playground);
    
    // we might aswell allow anyone to open?
    return 0;
	//return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

static int open_mem(struct inode *inode, struct file *filp)
{
    printk(KERN_INFO "[ka_mem] mem opened: %d\n", capable(CAP_SYS_RAWIO) ? 0 : -EPERM);
    printk(KERN_INFO "[ka_mem] high mem: %lx\n", (unsigned long)high_memory);
    printk(KERN_INFO "[ka_mem] file mode: %x\n", filp->f_mode);
    printk(KERN_INFO "[ka_mem] playground at: %llx\n", (unsigned long long)virt_to_phys((void*)playground));

    // we might aswell allow anyone to open?
    return 0;
    //return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

const struct file_operations mem_fops = {
    .llseek         = memory_lseek,
    .read           = read_mem,
    .write          = write_mem,
    .mmap           = mmap_mem,
    .open           = open_mem,
};

const struct file_operations kmem_fops = {
	.llseek		= memory_lseek,
	.read		= read_kmem,
	.write		= write_kmem,
	.mmap		= mmap_kmem,
	.open		= open_kmem,
};

