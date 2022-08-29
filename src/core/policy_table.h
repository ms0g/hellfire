#ifndef HELLFIRE_POLICY_TABLE_H
#define HELLFIRE_POLICY_TABLE_H

#include <linux/list.h>

enum HfPacketDestType {
    INPUT,
    OUTPUT
};

enum HfTargetType {
    ACCEPT,
    DROP
};

typedef struct {
    unsigned int id;                    /* Policy ID                */
    enum HfPacketDestType dest;         /* Packet destination type  */
    union {
        char* in;                       /* Ingress interface        */
        char* out;                      /* Egress interface         */
    } interface;
    char* pro;                          /* Protocol                 */
    union {
        u8 src[6];                      /* Source MAC address        */
    } mac;
    union {
        u32 src;                        /* Source IP address        */
        u32 dest;                       /* Destination IP address   */
    } ipaddr;
    struct {
        u16 src;                        /* Source port              */
        u16 dest;                       /* Destination port         */
    } port;
    enum HfTargetType target;           /* Rule                     */
    struct list_head list;
} HfPolicy;

HfPolicy* hfFindPolicy(int id, enum HfPacketDestType dest, const char* in, const char* out, const u8* sha,
                       const char* pro, u32 sip, u32 dip, u16 sport, u16 dport, enum HfTargetType target);

void hfCreatePolicy(char* pol);

void hfParsePolicy(HfPolicy* p, char* pol);

void hfDeletePolicy(int id, enum HfPacketDestType dest, const char* in, const char* out, const u8* sha,
                    const char* pro, u32 sip, u32 dip, u16 sport, u16 dport, enum HfTargetType target);

void hfCleanPolicyTable(void);

#define HFParseQuery(q, s) hfParsePolicy(q, s)

#endif //HELLFIRE_POLICY_TABLE_H
