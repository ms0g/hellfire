#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include "../netfilter/policy_table.h"
#include "../netfilter/hooks.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Sami GURPINAR <sami.gurpinar@gmail.com>");
MODULE_DESCRIPTION("Hellfire Char Device Driver");
MODULE_VERSION("0.1");

#define HF_IOC_MAGIC 0x73

#define HF_IOC_POL_FLUSH _IO(HF_IOC_MAGIC, 1)
#define HF_IOC_POL_LIST  _IOWR(HF_IOC_MAGIC, 2, char*)
#define HF_IOC_POL_DEL   _IOWR(HF_IOC_MAGIC, 3, char*)

#define DEV_NAME "hellfire"
#define BUFFER_SIZE 100


static int major_number;
static dev_t dev_num;
static struct cdev* mcdev;
static struct nf_hook_ops* ipingressho = NULL;
static struct nf_hook_ops* ipegressho = NULL;
static char device_buffer[BUFFER_SIZE];
int ret;

static int hf_open(struct inode* inode, struct file* filp);

static ssize_t hf_write(struct file* filp, const char __user* buf, size_t len, loff_t* offp);

static long hf_ioctl(struct file* filp, unsigned int cmd, unsigned long arg);

static int hf_release(struct inode* inode, struct file* filp);


static int hf_open(struct inode* inode, struct file* filp) {
    printk(KERN_INFO "%s: device opened successfully\n", DEV_NAME);
    return 0;
}

static int hf_release(struct inode* inode, struct file* filp) {
    printk(KERN_INFO "%s: device has been closed\n", DEV_NAME);
    return 0;
}

static long hf_ioctl(struct file* filp, unsigned int cmd, unsigned long arg) {
    size_t n;
    int num;
    char* pbuf;
    enum packet_dest_t d;
    char* chunk = NULL;
    policy_t* pol = NULL;
    pbuf = device_buffer;

    switch (cmd) {
        case HF_IOC_POL_LIST:
            printk(KERN_INFO "%s ioctl: HF_IOC_POL_LIST\n", DEV_NAME);

            if ((n = copy_from_user(device_buffer, (char*) arg, 100)) != 0) {
                printk(KERN_ALERT "%s: couldn't copy bytes from the user space %zu\n", DEV_NAME, n);
            }

            while ((chunk = strsep(&pbuf, ".")) != NULL) {
                if (!strcmp(chunk, "INPUT")) {
                    d = INPUT;
                } else if (chunk[0] == 'n') {
                    if ((ret = kstrtouint(&chunk[1], 10, &num)) != 0) {
                        printk(KERN_INFO "%s ioctl: wrong val %d for policy id\n", DEV_NAME, ret);
                        return ret;
                    }
                }
            }


            if ((pol = find_policy(num, d, NULL, NULL, NULL, 0, 0, 0, 0, 0)) != NULL) {
                if (d == INPUT)
                    snprintf(device_buffer, 100, "%d.%d.%s.%s.%u.%d.%d.", pol->id, pol->dest, pol->interface.in,
                             pol->pro, pol->ipaddr.src, pol->port.dest, pol->target);
                else
                    snprintf(device_buffer, 100, "%d.%d.%s.%s.%u.%d.%d.", pol->id, pol->dest, pol->interface.out,
                             pol->pro, pol->ipaddr.dest, pol->port.src, pol->target);

                if ((n = copy_to_user((char*) arg, device_buffer, strlen(device_buffer))) != 0) {
                    printk(KERN_ALERT "%s: couldn't copy bytes from the kernel space %zu\n", DEV_NAME, n);
                }
            }
            break;
        case HF_IOC_POL_DEL:
            printk(KERN_INFO "%s ioctl: HF_IOC_POL_DEL\n", DEV_NAME);

            if((n = copy_from_user(device_buffer, (char*) arg, 100)) != 0) {
                printk(KERN_ALERT "%s: couldn't copy bytes from the user space %zu\n", DEV_NAME, n);
            }

            while ((chunk = strsep(&pbuf, ".")) != NULL) {
                if (!strcmp(chunk, "INPUT")) {
                    d = INPUT;
                } else if (chunk[0] == 'n') {
                    if ((ret = kstrtouint(&chunk[1], 10, &num)) != 0) {
                        printk(KERN_INFO "%s ioctl: wrong val %d for policy id\n", DEV_NAME, ret);
                        return ret;
                    }
                }
            }
            delete_policy(num, d);
            printk(KERN_INFO "%s: deleted the policy %d\n", DEV_NAME, num);
            break;
        case HF_IOC_POL_FLUSH:
            clean_policy_table();
            printk(KERN_INFO "%s: flushed policy table\n", DEV_NAME);
            break;
    }
    return 0;
}

static ssize_t hf_write(struct file* filp, const char __user* buf, size_t len, loff_t* offp) {
    size_t maxdatalen = BUFFER_SIZE, n;

    if (len < BUFFER_SIZE) {
        maxdatalen = len;
    }

    if((n = copy_from_user(device_buffer, buf, maxdatalen)) != 0) {
        printk(KERN_ALERT "%s: couldn't copy bytes from the user space %zu\n", DEV_NAME, n);
    }

    device_buffer[maxdatalen] = 0;

    create_policy(device_buffer);

    return len;
}

static const struct file_operations fops = {    /* these are the file operations provided by our driver */
        .owner = THIS_MODULE,                   /* prevents unloading when operations are in use */
        .open = hf_open,                        /* to open the device */
        .unlocked_ioctl = hf_ioctl,             /* for another operations */
        .write = hf_write,                      /* to write to the device */
        .release = hf_release,                  /* to close the device */
};

static int __init hellfire_init(void) {
    /* Initialize IP Inbound netfilter hook */
    ipingressho = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    ipingressho->hook = (nf_hookfn*) ip_ingress_hook;   /* hook function */
    ipingressho->hooknum = NF_INET_PRE_ROUTING;         /* incoming packets */
    ipingressho->pf = NFPROTO_IPV4;                     /* IP */
    ipingressho->priority = NF_IP_PRI_FIRST;
    nf_register_hook(ipingressho);
    printk(KERN_INFO "%s: IP Ingress hook registered successfully\n", DEV_NAME);

    /* Initialize IP Outbound netfilter hook */
    ipegressho = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    ipegressho->hook = (nf_hookfn*) ip_egress_hook;     /* hook function */
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

    clean_policy_table();
    printk(KERN_INFO "%s: freed up the policy table\n", DEV_NAME);

    printk(KERN_INFO "%s: driver is exiting\n", DEV_NAME);
}

module_init(hellfire_init);
module_exit(hellfire_exit);

