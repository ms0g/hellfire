#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include "policy_table.h"
#include "hooks.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Sami GURPINAR <sami.gurpinar@gmail.com>");
MODULE_DESCRIPTION("Hellfire Char Device Driver");
MODULE_VERSION("0.3");

#define HF_IOC_MAGIC 0x73
#define HF_IOC_POL_FLUSH _IO(HF_IOC_MAGIC, 1)
#define HF_IOC_POL_DEL   _IOWR(HF_IOC_MAGIC, 2, char*)

#define DEV_NAME "hellfire"
#define BUFFER_SIZE 100

typedef HfPolicy HfQuery;

static int major_number;
static dev_t dev_num;
static struct cdev* mcdev;
static struct nf_hook_ops* ipingressho = NULL;
static struct nf_hook_ops* ipegressho = NULL;
static char device_buffer[BUFFER_SIZE];
int ret;

static int hfOpen(struct inode* inode, struct file* filp);

static ssize_t hfWrite(struct file* filp, const char __user* buf, size_t len, loff_t* offp);

static long hfIOctl(struct file* filp, unsigned int cmd, unsigned long arg);

static int hfRelease(struct inode* inode, struct file* filp);


static int hfOpen(struct inode* inode, struct file* filp) {
    printk(KERN_INFO "%s: device opened successfully\n", DEV_NAME);
    return 0;
}

static int hfRelease(struct inode* inode, struct file* filp) {
    printk(KERN_INFO "%s: device has been closed\n", DEV_NAME);
    return 0;
}

static long hfIOctl(struct file* filp, unsigned int cmd, unsigned long arg) {
    size_t n;
    HfQuery q;
    memset(&q, 0, sizeof(HfQuery));

    switch (cmd) {
        case HF_IOC_POL_DEL:
            printk(KERN_INFO "%s ioctl: HF_IOC_POL_DEL\n", DEV_NAME);

            if((n = copy_from_user(device_buffer, (char*) arg, 100)) != 0) {
                printk(KERN_ALERT "%s: couldn't copy bytes from the user space %zu\n", DEV_NAME, n);
            }

            HfParseQuery(&q, device_buffer);

            memset(device_buffer, 0, sizeof(device_buffer));

            if (hfDeletePolicy(q.id, q.dest, q.interface.in, q.interface.out, q.mac.src, q.pro, q.ipaddr.src,
                               q.ipaddr.dest, q.port.src, q.port.dest, q.target) == -1) {
                strcpy(device_buffer, "fail");
                printk(KERN_INFO "%s: failed to delete the policy\n", DEV_NAME);
            } else {
                strcpy(device_buffer, "success");
                printk(KERN_INFO "%s: success to delete the policy\n", DEV_NAME);
            }

            if ((n = copy_to_user((char*) arg, device_buffer, strlen(device_buffer))) != 0) {
                printk(KERN_ALERT "%s: couldn't copy bytes from the kernel space %zu\n", DEV_NAME, n);
            }

            break;
        case HF_IOC_POL_FLUSH:
            hfCleanPolicyTable();
            printk(KERN_INFO "%s: flushed policy table\n", DEV_NAME);
            break;
    }
    return 0;
}

static ssize_t hfWrite(struct file* filp, const char __user* buf, size_t len, loff_t* offp) {
    size_t maxdatalen = BUFFER_SIZE, n;

    if (len < BUFFER_SIZE) {
        maxdatalen = len;
    }

    if((n = copy_from_user(device_buffer, buf, maxdatalen)) != 0) {
        printk(KERN_ALERT "%s: couldn't copy bytes from the user space %zu\n", DEV_NAME, n);
    }

    device_buffer[maxdatalen] = 0;

    hfCreatePolicy(device_buffer);

    return len;
}

static const struct file_operations fops = {    /* these are the file operations provided by our driver */
        .owner = THIS_MODULE,                   /* prevents unloading when operations are in use */
        .open = hfOpen,                        /* to open the device */
        .unlocked_ioctl = hfIOctl,             /* for another operations */
        .write = hfWrite,                      /* to write to the device */
        .release = hfRelease,                  /* to close the device */
};

static int __init hellfire_init(void) {
    /* Initialize IP Inbound netfilter hook */
    ipingressho = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    ipingressho->hook = (nf_hookfn*) hfIpIngressHook;   /* hook function */
    ipingressho->hooknum = NF_INET_PRE_ROUTING;         /* incoming packets */
    ipingressho->pf = NFPROTO_IPV4;                     /* IP */
    ipingressho->priority = NF_IP_PRI_FIRST;
    nf_register_hook(ipingressho);
    printk(KERN_INFO "%s: IP Ingress hook registered successfully\n", DEV_NAME);

    /* Initialize IP Outbound netfilter hook */
    ipegressho = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    ipegressho->hook = (nf_hookfn*) hfIpEgressHook;     /* hook function */
    ipegressho->hooknum = NF_INET_POST_ROUTING;         /* outgoing packets */
    ipegressho->pf = NFPROTO_IPV4;                      /* IP */
    ipegressho->priority = NF_IP_PRI_FIRST;
    nf_register_hook(ipegressho);
    printk(KERN_INFO "%s: IP Egress hook registered successfully\n", DEV_NAME);

    /* we will get the major number dynamically */
    if ((ret = alloc_chrdev_region(&dev_num, 0, 1, DEV_NAME)) < 0) {
        printk(KERN_ALERT "%s: failed to allocate major number\n", DEV_NAME);
        return ret;
    } else
        printk(KERN_INFO "%s: major number allocated successfully\n", DEV_NAME);

    major_number = MAJOR(dev_num);
    printk(KERN_INFO "%s: major number of our device is %d\n", DEV_NAME, major_number);

    mcdev = cdev_alloc();       /* create, allocate and initialize our cdev structure */
    mcdev->ops = &fops;         /* fops stand for our file operations */
    mcdev->owner = THIS_MODULE;

    /* we have created and initialized our cdev structure now we need to add it to the kernel */
    if ((ret = cdev_add(mcdev, dev_num, 1)) < 0) {
        printk(KERN_ALERT "%s: device adding to the kernel failed\n", DEV_NAME);
        return ret;
    } else
        printk(KERN_INFO "%s: device addition to the kernel successfully\n", DEV_NAME);

    return 0;
}


static void __exit hellfire_exit(void) {
    nf_unregister_hook(ipingressho);
    kfree(ipingressho);
    printk(KERN_INFO "%s: unregistered IP Ingress hook\n", DEV_NAME);

    nf_unregister_hook(ipegressho);
    kfree(ipegressho);
    printk(KERN_INFO "%s: unregistered IP Egress hook\n", DEV_NAME);

    cdev_del(mcdev);
    printk(KERN_INFO "%s: removed the mcdev from kernel\n", DEV_NAME);

    unregister_chrdev_region(dev_num, 1);
    printk(KERN_INFO "%s: unregistered the device numbers\n", DEV_NAME);

    hfCleanPolicyTable();
    printk(KERN_INFO "%s: freed up the policy table\n", DEV_NAME);

    printk(KERN_INFO "%s: driver is exiting\n", DEV_NAME);
}

module_init(hellfire_init);
module_exit(hellfire_exit);

