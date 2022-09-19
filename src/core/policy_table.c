#include "policy_table.h"
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/in.h>
#include "macros.h"

#define HFNOMATCH  -1
#define HFSUCCESS   0
#define HFNOOP      1

static LIST_HEAD(policy_table);

static DEFINE_SPINLOCK(slock);

static HfPolicy* hfCheckIncomingPkt(HfPolicy* entry, const char* in, const u8* sha,
                                    u8 pro, u32 sip, u16 sport, u16 dport);

static HfPolicy* hfCheckOutgoingPkt(HfPolicy* entry, const char* out,
                                    u8 pro, u32 dip, u16 sport, u16 dport);

static inline int hfCheckInf(HfPolicy* entry, const char* in);

static inline int hfCheckIp(HfPolicy* entry, u32 ip);

static inline int hfCheckMac(HfPolicy* entry, const u8* mac);

static inline int hfCheckPro(HfPolicy* entry, u8 pro, int state, u16 sport, u16 dport);

static inline int hfCheckPort(HfPolicy* entry, u16 sport, u16 dport);

int hfCreatePolicy(char* pol) {
    static unsigned id = 1;
    unsigned long flags;
    HfPolicy* p;

    if ((p = (HfPolicy*) kmalloc(sizeof(HfPolicy), GFP_KERNEL)) == NULL) {
        printk(KERN_ALERT "hellfire: kmalloc failed\n");
        return -1;
    }

    memset(p, 0, sizeof(HfPolicy));

    p->id = id;

    hfParsePolicy(p, pol);

    INIT_LIST_HEAD(&p->list);

    spin_lock_irqsave(&slock, flags);
    list_add_tail(&p->list, &policy_table);
    spin_unlock_irqrestore(&slock, flags);
    ++id;
    return 0;
}

void hfParsePolicy(HfPolicy* p, char* pol) {
    char* chunk;
    u32 ip;
    u16 port;
    u8 pro;
    int num;

    while ((chunk = (char*) strsep(&pol, ".")) != NULL) {
        if (chunk[0] == 'd') {
            if (chunk[1] == '0')
                p->dest = INPUT;
            else
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
            if (kstrtou8(&chunk[1], 10, &pro) == 0)
                p->pro = pro;
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
            if (chunk[1] == '0')
                p->target = ACCEPT;
            else if (chunk[1] == '1')
                p->target = DROP;
        }
    }
}


int hfDeletePolicy(int id, enum HfPacketDestType dest, const char* in, const char* out, const u8* sha,
                    u8 pro, u32 sip, u32 dip, u16 sport, u16 dport, enum HfTargetType target) {
    HfPolicy* entry;
    unsigned long flags;

    if ((entry = hfFindPolicy(id, dest, in, out, sha, pro, sip, dip, sport, dport, target)) != NULL) {
        spin_lock_irqsave(&slock, flags);
        list_del(&entry->list);
        if (dest == INPUT) {
            if (entry->interface.in)
                kfree(entry->interface.in);
        } else {
            if (entry->interface.out)
                kfree(entry->interface.out);
        }

        kfree(entry);
        spin_unlock_irqrestore(&slock, flags);
        return 0;
    }
    return -1;
}

int hfCleanPolicyTable(void) {
    struct list_head* curr, * next;
    unsigned long flags;
    HfPolicy* entry;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &policy_table)
    {
        entry = list_entry(curr, HfPolicy, list);
        list_del(&entry->list);
        if (entry->dest == INPUT) {
            if (entry->interface.in)
                kfree(entry->interface.in);
        } else {
            if (entry->interface.out)
                kfree(entry->interface.out);
        }

        kfree(entry);
    }
    spin_unlock_irqrestore(&slock, flags);
    return 0;
}

HfPolicy* hfFindPolicy(int id, enum HfPacketDestType dest, const char* in, const char* out, const u8* sha,
                       u8 pro, u32 sip, u32 dip, u16 sport, u16 dport, enum HfTargetType target) {
    HfPolicy* entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_entry(entry, &policy_table, list)
    {
        if (entry->id == id && entry->dest == dest) {
            spin_unlock_irqrestore(&slock, flags);
            return entry;
        } else if (dest == INPUT && entry->dest == INPUT) {
            if (hfCheckIncomingPkt(entry, in, sha, pro, sip, sport, dport)) {
                spin_unlock_irqrestore(&slock, flags);
                return entry;
            }
        } else if (dest == OUTPUT && entry->dest == OUTPUT) {
            if (hfCheckOutgoingPkt(entry, out, pro, dip, sport, dport)) {
                spin_unlock_irqrestore(&slock, flags);
                return entry;
            }
        }
    }
    spin_unlock_irqrestore(&slock, flags);
    return NULL;
}

HfPolicy* hfCheckIncomingPkt(HfPolicy* entry, const char* in, const u8* sha,
                             u8 pro, u32 sip, u16 sport, u16 dport) {
    int found = 0;
    if (hfCheckInf(entry, in) == HFSUCCESS) {
        found = 1;
        if (hfCheckIp(entry, sip) == HFNOMATCH) {
            found = 0;
        } else if (hfCheckMac(entry, sha) == HFNOMATCH) {
            found = 0;
        }
        if (hfCheckPro(entry, pro, found, sport, dport) == HFNOMATCH)
            found = 0;
    } else if (hfCheckMac(entry, sha) == HFSUCCESS) {
        found = 1;
        if (hfCheckPro(entry, pro, found, sport, dport) == HFNOMATCH)
            found = 0;
    } else if (hfCheckPro(entry, pro, 1, sport, dport) == HFSUCCESS) {
        found = 1;
        if (hfCheckIp(entry, sip) == HFNOMATCH) {
            found = 0;
        }
    } else if (hfCheckIp(entry, sip) == HFSUCCESS) {
        found = 1;
    }

    if (found)
        return entry;
    else
        return NULL;

}


HfPolicy* hfCheckOutgoingPkt(HfPolicy* entry, const char* out, u8 pro, u32 dip, u16 sport, u16 dport) {
    int found = 0;
    if (hfCheckInf(entry, out) == HFSUCCESS) {
        found = 1;
        if (hfCheckIp(entry, dip) == HFNOMATCH) {
            found = 0;
        }
        if (hfCheckPro(entry, pro, found, sport, dport) == HFNOMATCH)
            found = 0;
    } else if (hfCheckPro(entry, pro, found, sport, dport) == HFSUCCESS) {
        found = 1;
        if (hfCheckIp(entry, dip) == HFNOMATCH) {
            found = 0;
        }
    } else if (hfCheckIp(entry, dip) == HFSUCCESS) {
        found = 1;
    }

    if (found)
        return entry;
    else
        return NULL;
}

int hfCheckInf(HfPolicy* entry, const char* in) {
    if (entry->interface.in && in) {
        return IS_EQUAL(entry->interface.in, in) ? HFSUCCESS : HFNOMATCH;
    }
    return HFNOOP;
}

int hfCheckIp(HfPolicy* entry, u32 ip) {
    switch (entry->dest) {
        case INPUT:
            if (entry->ipaddr.src && ip) {
                return entry->ipaddr.src == ip ? HFSUCCESS : HFNOMATCH;
            }
            break;
        case OUTPUT:
            if (entry->ipaddr.dest && ip) {
                return entry->ipaddr.dest == ip ? HFSUCCESS : HFNOMATCH;
            }
            break;
    }
    return HFNOOP;
}

int hfCheckMac(HfPolicy* entry, const u8* mac) {
    if (!IS_MAC_ADDR_EMPTY(entry->mac.src) && mac) {
        return memcmp(entry->mac.src, mac, 6) == 0 ? HFSUCCESS : HFNOMATCH;
    }
    return HFNOOP;
}

int hfCheckPro(HfPolicy* entry, u8 pro, int state, u16 sport, u16 dport) {
    if (state && entry->pro && pro) {
        if (entry->pro != pro)
            return HFNOMATCH;
        return entry->pro !=  IPPROTO_ICMP ? hfCheckPort(entry, sport, dport) : HFSUCCESS;

    }
    return HFNOOP;
}

int hfCheckPort(HfPolicy* entry, u16 sport, u16 dport) {
    switch (entry->dest) {
        case INPUT:
            if (entry->port.dest && dport) {
                return entry->port.dest == dport ? HFSUCCESS : HFNOMATCH;
            }
            break;
        case OUTPUT:
            if (entry->port.dest && dport) {
                return entry->port.dest == dport ? HFSUCCESS : HFNOMATCH;
            } else if (entry->port.src && sport) {
                return entry->port.src == sport ? HFSUCCESS : HFNOMATCH;
            }
            break;
    }
    return HFNOOP;
}
