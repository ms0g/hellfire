#include "policy_table.h"
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "macros.h"

#define SUCCESS 0
#define ERRNOTFOUND 1

static LIST_HEAD(policy_table);

static DEFINE_SPINLOCK(slock);

static policy_t* check_if_input(policy_t* entry, const char* in, const u8* sha,
                                const char* pro, u32 sip, u16 sport, u16 dport);

static policy_t* check_if_output(policy_t* entry, const char* out,
                                 const char* pro, u32 dip, u16 sport, u16 dport);

static inline int check_inf(policy_t* entry, const char* in);

static inline int check_ip(policy_t* entry, u32 ip);

static inline int check_mac(policy_t* entry, const u8* mac);

static inline int check_pro(policy_t* entry, const char* pro, int state, u16 sport, u16 dport);

static inline int check_port(policy_t* entry, u16 sport, u16 dport);

void create_policy(char* pol) {
    static unsigned id = 1;
    unsigned long flags;
    policy_t* p;

    if ((p = (policy_t*) kmalloc(sizeof(policy_t), GFP_KERNEL)) == NULL) {
        printk(KERN_ALERT "hellfire: kmalloc failed\n");
        return;
    }

    memset(p, 0, sizeof(policy_t));

    p->id = id;

    parse_policy(p, pol);

    INIT_LIST_HEAD(&p->list);

    spin_lock_irqsave(&slock, flags);
    list_add_tail(&p->list, &policy_table);
    spin_unlock_irqrestore(&slock, flags);
    ++id;
}

void parse_policy(policy_t* p, char* pol) {
    char* chunk;
    u32 ip;
    u16 port;
    int num;

    while ((chunk = (char*) strsep(&pol, ".")) != NULL) {
        if (!strcmp(chunk, "INPUT")) {
            p->dest = INPUT;
        } else if (!strcmp(chunk, "OUTPUT")) {
            p->dest = OUTPUT;
        } else if (chunk[0] == 'n') {
            if (kstrtouint(&chunk[1], 10, &num) == 0) {
                p->id = num;
            }
        } else if (chunk[0] == 'i') {
            p->interface.in = kmalloc(strlen(&chunk[1]), GFP_KERNEL);
            strcpy(p->interface.in, &chunk[1]);
        } else if (chunk[0] == 'o') {
            p->interface.out = kmalloc(strlen(&chunk[1]), GFP_KERNEL);
            strcpy(p->interface.out, &chunk[1]);
        } else if (chunk[0] == 'p') {
            p->pro = kmalloc(strlen(&chunk[1]), GFP_KERNEL);
            strcpy(p->pro, &chunk[1]);
        } else if (!strncmp(chunk, "sm", 2)) {
            sscanf(&chunk[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &p->mac.src[0],
                   &p->mac.src[1],
                   &p->mac.src[2],
                   &p->mac.src[3],
                   &p->mac.src[4],
                   &p->mac.src[5]);
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
}


void delete_policy(int id, enum PacketDestType dest, const char* in, const char* out, const u8* sha,
                   const char* pro, u32 sip, u32 dip, u16 sport, u16 dport, enum TargetType target) {
    policy_t* entry;
    unsigned long flags;

    if ((entry = find_policy(id, dest, in, out, sha, pro, sip, dip, sport, dport, target)) != NULL) {
        spin_lock_irqsave(&slock, flags);
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

void clean_policy_table(void) {
    struct list_head* curr, * next;
    unsigned long flags;
    policy_t* entry;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &policy_table)
    {
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

policy_t* find_policy(int id, enum PacketDestType dest, const char* in, const char* out, const u8* sha,
                      const char* pro, u32 sip, u32 dip, u16 sport, u16 dport, enum TargetType target) {
    policy_t* entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_entry(entry, &policy_table, list)
    {
        if (entry->id == id && entry->dest == dest) {
            spin_unlock_irqrestore(&slock, flags);
            return entry;
        } else if (dest == INPUT && entry->dest == INPUT) {
            if (check_if_input(entry, in, sha, pro, sip, sport, dport)) {
                spin_unlock_irqrestore(&slock, flags);
                return entry;
            }
        } else if (dest == OUTPUT && entry->dest == OUTPUT) {
            if (check_if_output(entry, out, pro, dip, sport, dport)) {
                spin_unlock_irqrestore(&slock, flags);
                return entry;
            }
        }
    }
    spin_unlock_irqrestore(&slock, flags);
    return NULL;
}

policy_t* check_if_input(policy_t* entry, const char* in, const u8* sha,
                         const char* pro, u32 sip, u16 sport, u16 dport) {
    int found = 0;
    if (check_inf(entry, in) == 0) {
        found = 1;
        if (check_ip(entry, sip) != 0) {
            found = 0;
        } else if (check_mac(entry, sha) != 0) {
            found = 0;
        }
        if (check_pro(entry, pro, found, sport, dport) != 0)
            found = 0;
    } else if (check_mac(entry, sha) == 0) {
        found = 1;
        if (check_pro(entry, pro, found, sport, dport) != 0)
            found = 0;
    } else if (check_pro(entry, pro, found, sport, dport) == 0) {
        if (check_ip(entry, sip) != 0) {
            found = 0;
        }
    } else if (check_ip(entry, sip) == 0) {
        found = 1;
    }

    if (found)
        return entry;
    else
        return NULL;

}


policy_t* check_if_output(policy_t* entry, const char* out, const char* pro, u32 dip, u16 sport, u16 dport) {
    int found = 0;
    if (check_inf(entry, out) == 0) {
        found = 1;
        if (check_ip(entry, dip) != 0) {
            found = 0;
        }
        if (check_pro(entry, pro, found, sport, dport) != 0)
            found = 0;
    } else if (check_pro(entry, pro, found, sport, dport) == 0) {
        if (check_ip(entry, dip) != 0) {
            found = 0;
        }
    } else if (check_ip(entry, dip) == 0) {
        found = 1;
    }

    if (found)
        return entry;
    else
        return NULL;
}

int check_inf(policy_t* entry, const char* in) {
    if (entry->interface.in && in) {
        if (IS_EQUAL(entry->interface.in, in)) return SUCCESS;
    }
    return -ERRNOTFOUND;
}

int check_ip(policy_t* entry, u32 ip) {
    switch (entry->dest) {
        case INPUT:
            if (entry->ipaddr.src && ip) {
                if (entry->ipaddr.src == ip) return SUCCESS;

            }
        case OUTPUT:
            if (entry->ipaddr.dest && ip) {
                if (entry->ipaddr.dest == ip) return SUCCESS;
            }
    }
    return -ERRNOTFOUND;
}

int check_mac(policy_t* entry, const u8* mac) {
    if (!IS_MAC_ADDR_EMPTY(entry->mac.src) && mac) {
        if (memcmp(entry->mac.src, mac, 6) == 0) return SUCCESS;
    }
    return -ERRNOTFOUND;
}

int check_pro(policy_t* entry, const char* pro, int state, u16 sport, u16 dport) {
    if (state && entry->pro && pro) {
        if (IS_EQUAL(entry->pro, pro)) {
            if (!IS_EQUAL(entry->pro, "icmp"))
                return check_port(entry, sport, dport);
        }
    }
    return SUCCESS;
}

int check_port(policy_t* entry, u16 sport, u16 dport) {
    switch (entry->dest) {
        case INPUT:
            if (entry->port.dest && dport) {
                if (entry->port.dest == dport) return SUCCESS;
            }
        case OUTPUT:
            if (entry->port.dest && dport) {
                if (entry->port.dest == dport) return SUCCESS;
            } else if (entry->port.src && sport) {
                if (entry->port.src == sport) return SUCCESS;
            }
    }
    return -ERRNOTFOUND;
}
