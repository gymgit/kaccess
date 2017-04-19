#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/types.h>   // for dev_t typedef
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "kacmd.h"
#include "kaccess.h"

static ssize_t read_res(struct file *filp, char __user *buf,
			 size_t count, loff_t *ppos)
{
    unsigned long p = *ppos;
    size_t to_cpy = 0;
    struct cmd_result* cr = (struct cmd_result*)filp->private_data; 
    if (cr->resptr && cr->ready) {
        printk(KERN_INFO "[ka_cmd] Reading results");
        to_cpy = cr->size - p <= count ? cr->size - cr->pos : count;
        if (copy_to_user(buf, cr->resptr, to_cpy)) {
            printk(KERN_ALERT "[ka_cmd] Failed to copy-to-user");
		    return -EFAULT;
		}
    } else {
        printk(KERN_INFO "[ka_cmd] Nothing to read");
        return 0;
    }
    *ppos += to_cpy;
    return to_cpy;

}

static ssize_t write_cmd(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
    struct cmd_result* cr = (struct cmd_result*)filp->private_data; 
    char* ud = kmalloc(count, GFP_KERNEL);
    void* addr;
    if (!ud){
        printk(KERN_ALERT "[ka_cmd] Failed to allocate tmp buffer");
        return -EFAULT;
    }
    // invalidate prev data
    if (cr->resptr){
        kfree(cr->resptr);
        cr->resptr = NULL;
    }
    memset(cr, 0, sizeof(struct cmd_result));
    *ppos = 0;

    if(copy_from_user(ud, buf, count)){
        printk(KERN_ALERT "[ka_cmd] Failed to copy-from-user");
        goto error_out;
    }

    printk(KERN_INFO "[ka_cmd] Invoking CMD %c", buf[0]);
    switch(buf[0]){
        case KACMD_JUMP_TO:
            memcpy(&addr, buf + 1, sizeof(void*)); 
            printk(KERN_INFO "[ka_cmd] Jumping to %llx", (unsigned long long)addr);

            break;
        case KACMD_CALL:
            break;
        default:
            printk(KERN_INFO "[ka_cmd] Unknown CMD %c", buf[0]);
            break;
    }

    kfree(ud);
    return count;
error_out:
    kfree(ud);
    return -EFAULT;
}

static int open_cmd(struct inode *inode, struct file *filp)
{
    printk(KERN_INFO "[ka_cmd] kaCMD opened, exec page at: %llx\n",(unsigned long long)execplay);
    filp->private_data = kmalloc(sizeof(struct cmd_result), GFP_KERNEL);
    if (!filp->private_data){
        printk(KERN_ALERT "[ka_cmd] Failed to allocate private_data\n");
        return -ENOMEM;
    }
    memset(filp->private_data, 0, sizeof(struct cmd_result));

    return 0;
}

static int close_cmd(struct inode *inode, struct file *filp)
{
    struct cmd_result* cr = (struct cmd_result*)filp->private_data; 
    printk(KERN_INFO "[ka_cmd] kaCMD closed");
    if (cr){
        if (cr->resptr){
            kfree(cr->resptr);
            cr->resptr = NULL;
        }
        kfree(cr);
        filp->private_data = NULL;
    }

    return 0;
}

const struct file_operations cmd_fops = {
    .read           = read_res,
    .write          = write_cmd,
    .open           = open_cmd,
    .release        = close_cmd,
};
