#include "policy_table.h"
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/slab.h>


LIST_HEAD(policy_table);

DEFINE_SPINLOCK(slock);
unsigned long flags;

static policy_t* check_if_input(policy_t* entry, char* in, char* pro, u32 sip, u16 dport);

static policy_t* check_if_output(policy_t* entry, char* out, char* pro, u32 dip, u16 sport);

policy_t* find_policy(int id, enum packet_dest_t dest, char* in, char* out, char* pro,
                      u32 sip, u32 dip, u16 sport, u16 dport, enum target_t target) {
    policy_t* entry;

    spin_lock_irqsave(&slock, flags);
    list_for_each_entry(entry, &policy_table, list) {
        if (entry->id == id) {
            spin_unlock_irqrestore(&slock, flags);
            return entry;
        } else if (dest == INPUT && entry->dest == INPUT) {
            if (check_if_input(entry, in, pro, sip, dport)) {
                spin_unlock_irqrestore(&slock, flags);
                return entry;
            }
        } else if (dest == OUTPUT && entry->dest == OUTPUT) {
            if (check_if_output(entry, out, pro, dip, sport)) {
                spin_unlock_irqrestore(&slock, flags);
                return entry;
            }
        }
    }
    spin_unlock_irqrestore(&slock, flags);
    return NULL;
}


policy_t* check_if_input(policy_t* entry, char* in, char* pro, u32 sip, u16 dport) {
    int check = 0;
    if (entry->interface.in && in) {
        if (!strcmp(entry->interface.in, in)) {
            check = 1;
            if (entry->pro && pro) {
                if (!strcmp(entry->pro, pro)) {
                    if (strcmp(pro, "icmp") != 0) {
                        if (entry->port.dest)
                            if (entry->port.dest != dport)
                                check = 0;
                    }
                } else check = 0;
            }
            if (check && entry->ipaddr.src) {
                if (entry->ipaddr.src != sip)
                    check = 0;
            }
        }
    } else if (entry->pro && pro) {
        if (!strcmp(entry->pro, pro)) {
            check = 1;
            if (strcmp(pro, "icmp") != 0) {
                if (entry->port.dest)
                    if (entry->port.dest != dport)
                        check = 0;
            }
            if (check && entry->ipaddr.src) {
                if (entry->ipaddr.src != sip)
                    check = 0;
            }
        }
    } else if (entry->ipaddr.src) {
        if (entry->ipaddr.src == sip)
            check = 1;
    }

    if (check)
        return entry;
    else
        return NULL;

}


policy_t* check_if_output(policy_t* entry, char* out, char* pro, u32 dip, u16 sport) {
    int check = 0;

    if (entry->interface.out && out) {
        if (!strcmp(entry->interface.out, out)) {
            check = 1;
            if (entry->pro && pro) {
                if (!strcmp(entry->pro, pro)) {
                    if (strcmp(pro, "icmp") != 0) {
                        if (entry->port.src)
                            if (entry->port.src != sport)
                                check = 0;
                    }
                } else check = 0;
            }
            if (check && entry->ipaddr.dest) {
                if (entry->ipaddr.dest != dip)
                    check = 0;
            }
        }
    } else if (entry->pro && pro) {
        if (!strcmp(entry->pro, pro)) {
            check = 1;
            if (strcmp(pro, "icmp") != 0) {
                if (entry->port.src)
                    if (entry->port.src != sport)
                        check = 0;
            }
            if (check && entry->ipaddr.dest) {
                if (entry->ipaddr.dest != dip)
                    check = 0;
            }
        }
    } else if (entry->ipaddr.dest) {
        if (entry->ipaddr.dest == dip)
            check = 1;
    }

    if (check)
        return entry;
    else
        return NULL;

}

void create_policy(char* pol) {
    static unsigned id = 1;
    policy_t* p;
    char* chunk;
    u32 ip;
    u16 port;

    p = (policy_t*) kmalloc(sizeof(policy_t), GFP_KERNEL);
    if (!p) {
        printk(KERN_ALERT "hellfire: kmalloc failed\n");
        return;
    }

    memset(p, 0, sizeof(policy_t));

    p->id = id;
    while ((chunk = strsep(&pol, ".")) != NULL) {
        if (!strcmp(chunk, "INPUT")) {
            p->dest = INPUT;
        } else if (!strcmp(chunk, "OUTPUT")) {
            p->dest = OUTPUT;
        } else if (chunk[0] == 'i') {
            p->interface.in = kmalloc(strlen(&chunk[1]), GFP_KERNEL);
            strcpy(p->interface.in, &chunk[1]);
        } else if (chunk[0] == 'o') {
            p->interface.out = kmalloc(strlen(&chunk[1]), GFP_KERNEL);
            strcpy(p->interface.out, &chunk[1]);
        } else if (chunk[0] == 'p') {
            p->pro = kmalloc(strlen(&chunk[1]), GFP_KERNEL);
            strcpy(p->pro, &chunk[1]);
        } else if (!strncmp(chunk, "si", 2)) {
            if (kstrtouint(&chunk[2], 10, &ip) == 0)
                p->ipaddr.src = ip;
        } else if (!strncmp(chunk, "di", 2)) {
            if (kstrtouint(&chunk[2], 10, &ip) == 0)
                p->ipaddr.dest = ip;
        } else if (!strncmp(chunk, "sp", 2)) {
            if (kstrtou16(&chunk[2], 10, &port) == 0)
                p->port.src = port;
        } else if (!strncmp(chunk, "dp", 2)) {
            if (kstrtou16(&chunk[2], 10, &port) == 0)
                p->port.dest = port;
        } else if (chunk[0] == 't') {
            if (!strcmp(&chunk[1], "ACCEPT"))
                p->target = ACCEPT;
            else if (!strcmp(&chunk[1], "DROP"))
                p->target = DROP;
        }
    }
    INIT_LIST_HEAD(&p->list);

    spin_lock_irqsave(&slock, flags);
    list_add_tail(&p->list, &policy_table);
    spin_unlock_irqrestore(&slock, flags);
    ++id;
}

void delete_policy(int id, enum packet_dest_t dest) {
    struct list_head* curr, *next;
    policy_t* entry;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &policy_table) {
        entry = list_entry(curr, policy_t, list);
        if (entry->id == id) {
            list_del(&entry->list);
            if (dest == INPUT) {
                if (entry->interface.in)
                    kfree(entry->interface.in);
            } else {
                if (entry->interface.out)
                    kfree(entry->interface.out);
            }

            if (entry->pro)
                kfree(entry->pro);
            kfree(entry);
            spin_unlock_irqrestore(&slock, flags);
        }
    }
}

void clean_policy_table(void) {
    struct list_head* curr, *next;
    policy_t* entry;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &policy_table) {
        entry = list_entry(curr, policy_t, list);
        list_del(&entry->list);
        if (entry->dest == INPUT) {
            if (entry->interface.in)
                kfree(entry->interface.in);
        } else {
            if (entry->interface.out)
                kfree(entry->interface.out);
        }

        if (entry->pro)
            kfree(entry->pro);
        kfree(entry);
    }
    spin_unlock_irqrestore(&slock, flags);
}