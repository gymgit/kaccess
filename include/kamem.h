#ifndef KERNAL_ACCESS_MODULE_KAMEM_H
#define KERNAL_ACCESS_MODULE_KAMEM_H

#include <linux/fs.h>      // for alloc_chrdev_region()
#include <linux/types.h>   // for dev_t typedef
//#include <linux/kdev_t.h>  // for format_dev_t

extern long (*vread_p)(char *, char*, unsigned long);
extern long (*vwrite_p)(char*, char*, unsigned long);

// static loff_t memory_lseek(struct file *file, loff_t offset, int orig);
// static int open_kmem(struct inode *inode, struct file *filp);
// static ssize_t write_kmem(struct file *file, const char __user *buf,
// 			  size_t count, loff_t *ppos);
// static ssize_t read_kmem(struct file *file, const char __user *buf,
// 				size_t count, loff_t *ppos);
// static int mmap_kmem(struct file *file, struct vm_area_struct *vma);

extern const struct file_operations kmem_fops;
#endif
