#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/device.h>

#include <linux/types.h>   // for dev_t typedef
#include <linux/kdev_t.h>  // for format_dev_t
#include <linux/fs.h>      // for alloc_chrdev_region()
#include <linux/string.h>
#include <linux/kallsyms.h>

// for allocating playground2
#include <linux/vmalloc.h>
// io.h pulls this in
//#include <asm/pgtype_types.h>

#include <asm/io.h> //for debug purposes

//#include "kaccess.h"
#include "kamem.h"
#include "kacmd.h"

#define DEVICE_NAME "kaccess"
#define DEVICE_CLASS "kutilities"


MODULE_AUTHOR("gym");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("This module provides access to the kernel");
MODULE_VERSION("0.1");

int majorNum;
struct class* kmemClass = NULL;
struct device* tmpDev = NULL;

char playground[] = "This is to test read writes into the kernel!";
char* execplay;

//static DEFINE_SPINLOCK(vmap_area_lock);

static int symwalk_cb(void *data, const char *name, struct module *mod, unsigned long addr)
{
    if (mod != NULL)
        return 0;

    if (strcmp(name, "vread") == 0)
    {
        if (vread_p != NULL)
        {
            printk(KERN_INFO "[kaccess] found two vread, terminating\n");
            return -EFAULT;
        }
        printk(KERN_INFO "[kaccess] found vread at %lx \n", addr);
        vread_p = (typeof(vread_p))addr;
        return 0;
    }
    if (strcmp(name, "vwrite") == 0)
    {
        if (vwrite_p != NULL)
        {
            printk(KERN_INFO "[kaccess] found two vwrite, terminating\n");
            return -EFAULT;
        }
        printk(KERN_INFO "[kaccess] found vwrite at %lx \n", addr);
        vwrite_p = (typeof(vwrite_p))addr;
        return 0;
    }
    return 0;
}
static const struct kadev {
        const char *name;
        umode_t mode;
        const struct file_operations *fops;
        fmode_t fmode;
} devlist[] = {
    [1] = { "ka_kmem", 0666, &kmem_fops, FMODE_UNSIGNED_OFFSET },
    [2] = { "ka_mem", 0666, &mem_fops, FMODE_UNSIGNED_OFFSET },
    [3] = { "ka_cmd", 0666, &cmd_fops, 0 },
};

static int memory_open(struct inode *inode, struct file *filp)
{
        int minor;
        const struct kadev *dev;

        minor = iminor(inode);
        if (minor >= ARRAY_SIZE(devlist))
                return -ENXIO;

        dev = &devlist[minor];
        if (!dev->fops)
                return -ENXIO;

        filp->f_op = dev->fops;
        filp->f_mode |= dev->fmode;

        if (dev->fops->open)
                return dev->fops->open(inode, filp);

        return 0;
}

static const struct file_operations memory_fops = {
        .open = memory_open,
        .llseek = noop_llseek,
};

static char *mem_devnode(struct device *dev, umode_t *mode)
{
        if (mode && devlist[MINOR(dev->devt)].mode)
                *mode = devlist[MINOR(dev->devt)].mode;
        return NULL;
}

static int __init chr_dev_init(void)
{

    int ret, minor;
	printk(KERN_INFO "[kaccess] MyKmem is loading\n");
    ret = kallsyms_on_each_symbol(symwalk_cb, NULL);
    if (ret){
        return ret;
    }
    
	majorNum = register_chrdev(0, DEVICE_NAME, &memory_fops);
	if (majorNum < 0){
		printk(KERN_ALERT "[kaccess] unable to get major for MyKmem\n");
		return majorNum;
	}

	kmemClass = class_create(THIS_MODULE, DEVICE_CLASS);
	if (IS_ERR(kmemClass)){
		unregister_chrdev(majorNum, DEVICE_NAME);
		printk(KERN_ALERT "[kaccess] Failed to register kmem class\n");
		return PTR_ERR(kmemClass);
	}

	
	//printk(KERN_INFO "[kaccess] Registering Minors\n");
	kmemClass->devnode = mem_devnode;
	for (minor = 1; minor < ARRAY_SIZE(devlist); minor++) {
		if (!devlist[minor].name)
			continue;

	    printk(KERN_INFO "[kaccess] Trying to Register %s with %d\n", devlist[minor].name, minor);
		tmpDev = device_create(kmemClass, NULL, MKDEV(majorNum, minor),
			      NULL, devlist[minor].name);
        if (IS_ERR(tmpDev)){
            class_destroy(kmemClass);
            unregister_chrdev(majorNum, DEVICE_NAME);
            printk(KERN_ALERT "[kaccess] Failed to register minor %d for %s\n", minor, devlist[minor].name);
            return PTR_ERR(tmpDev);
        }
	}
    /*
	kmemDev = device_create(kmemClass, NULL, MKDEV(majorNum, 0), NULL, DEVICE_NAME);
	if (IS_ERR(kmemDev)){
        class_destroy(kmemClass);
		unregister_chrdev(majorNum, DEVICE_NAME);
		printk(KERN_ALERT "[kaccess] Failed to register kmem class\n");
		return PTR_ERR(kmemDev);
	}*/
    execplay = __vmalloc(4096, GFP_KERNEL, PAGE_KERNEL_EXEC);
    //play =  playground;
    printk(KERN_INFO "[kaccess] playground at(virt): %llx\n", (unsigned long long)playground);
    printk(KERN_INFO "[kaccess] playground at(phys): %llx\n", (unsigned long long)virt_to_phys(playground));
    printk(KERN_INFO "[kaccess] executable page at: %llx\n", (unsigned long long)execplay);
    printk(KERN_INFO "[kaccess] KAccess device created\n");
    return 0;
}

static void __exit kmem_exit(void){
    int minor;
    for (minor = 1; minor < ARRAY_SIZE(devlist); minor++) {
        device_destroy(kmemClass, MKDEV(majorNum, minor));     // remove the device
    }
    device_destroy(kmemClass, MKDEV(majorNum, 0));     // remove the device
    class_unregister(kmemClass);                          // unregister the device class
    class_destroy(kmemClass);                             // remove the device class
    unregister_chrdev(majorNum, DEVICE_NAME);             // unregister the major number
    if (execplay) vfree(execplay);
    printk(KERN_INFO "[kaccess] Goodbye from the LKM!\n");

}

module_init(chr_dev_init);
module_exit(kmem_exit);
