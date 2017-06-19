#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/types.h>   // for dev_t typedef
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "kacmd.h"
#include "kaccess.h"

//extern char* playground;
//extern char* execplay;

static ssize_t read_res(struct file *filp, char __user *buf,
			 size_t count, loff_t *ppos)
{
    unsigned long p = *ppos;
    size_t to_cpy = 0;
    struct cmd_result* cr = (struct cmd_result*)filp->private_data; 
    if (cr->resptr && cr->ready) {
        printk(KERN_INFO "[ka_cmd] Reading results\n");
        to_cpy = cr->size - p <= count ? cr->size - cr->pos : count;
        if (copy_to_user(buf, cr->resptr, to_cpy)) {
            printk(KERN_ALERT "[ka_cmd] Failed to copy-to-user\n");
		    return -EFAULT;
		}
    } else {
        printk(KERN_INFO "[ka_cmd] Nothing to read\n");
        return 0;
    }
    *ppos += to_cpy;
    return to_cpy;

}

static void *add_result(struct cmd_result* cr, size_t size)
{
    cr->ready = 0;
    cr->pos = 0;
    if(cr->resptr)
    {
        kfree(cr->resptr);
        cr->resptr = NULL;
    }
    if(size)
    {
        cr->resptr = kmalloc(size, GFP_KERNEL);
        if (!cr->resptr)
        {
            printk(KERN_ALERT "[ka_cmd] kmalloc failed to allocate memory for response\n");
            return NULL;
        }
    }
    cr->size = size;
    return cr->resptr;
}

static ssize_t write_cmd(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
    struct cmd_result* cr = (struct cmd_result*)filp->private_data; 
    char* ud = kmalloc(count, GFP_KERNEL);
    if (!ud){
        printk(KERN_ALERT "[ka_cmd] Failed to allocate tmp buffer\n");
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
        printk(KERN_ALERT "[ka_cmd] Failed to copy-from-user\n");
        goto error_out;
    }

    printk(KERN_INFO "[ka_cmd] Invoking CMD %c\n", ud[0]);
    switch(ud[0]){
        case KACMD_JUMP_TO:
        {
            struct kacmd_jump_params *kjp = (struct kacmd_jump_params*)ud;
            printk(KERN_INFO "[ka_cmd] Jumping to %llx\n", (unsigned long long) kjp->address);
            goto *kjp->address;
            break;
        }
        case KACMD_CALL_SIMPLE:
        {
            struct kacmd_call_params *kcp = (struct kacmd_call_params*)ud;
            printk(KERN_INFO "[ka_cmd] Calling %llx\n", (unsigned long long) kcp->address);
            kcp->address();
            break;
        }
        case KACMD_CALL_COMPLEX:
        {
            //struct kacmd_call_params *kcp = (struct kacmd_call_params*)ud;
            printk(KERN_INFO "[ka_cmd] Not Implemented\n");
            break;
        }
        case KACMD_KMALLOC:
        {
            struct kacmd_kmalloc_params *kkp = (struct kacmd_kmalloc_params*)ud;
            unsigned int flag = kkp->flag == 0? GFP_KERNEL : kkp->flag;
            void *result;
            struct kacmd_kmalloc_resp *kkr;
            printk(KERN_INFO "[ka_cmd] Calling kmalloc, size: %lx flags: %x\n", kkp->size, flag);
            result = kmalloc(kkp->size, flag);
            if (!result){
                printk(KERN_ALERT "[ka_cmd] kmalloc failed to allocate memory\n");
                goto error_out;
            }
            kkr = (struct kacmd_kmalloc_resp *) add_result(cr, sizeof(struct kacmd_kmalloc_resp));
            if (!kkr)
            {   
                kfree(result);
                goto error_out;
            }
            kkr->size = kkp->size;
            kkr->address = result;
            cr->ready = 1;
            break;
        }
        case KACMD_KFREE:
        {
            struct kacmd_kfree_params *kkfp = (struct kacmd_kfree_params*)ud;
            printk(KERN_INFO "[ka_cmd] Calling kfree, size: %p\n", kkfp->address);
            kfree(kkfp->address);
            break;

        }
        case KACMD_INFO:
        {
            //struct kacmd_info_params *kip = (struct kacmd_info_params*)ud;
            struct kacmd_info_resp *kir = (struct kacmd_info_resp *)add_result(cr, sizeof(struct kacmd_info_resp));
            printk(KERN_INFO "[ka_cmd] Providing info\n");
            kir->pg_vaddress = playground;
            kir->pg_paddress = virt_to_phys(playground);
            kir->exec_paddress = execplay;
            cr->ready = 1;
            break;
        }
        default:
            printk(KERN_INFO "[ka_cmd] Unknown CMD %c\n", buf[0]);
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
    printk(KERN_INFO "[ka_cmd] kaCMD closed\n");
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
