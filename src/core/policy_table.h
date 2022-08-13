#ifndef HELLFIRE_POLICY_TABLE_H
#define HELLFIRE_POLICY_TABLE_H

#include <linux/list.h>

enum PacketDestType {
    INPUT,
    OUTPUT
};

enum TargetType {
    ACCEPT,
    DROP
};

typedef struct {
    unsigned int id;                     /* Policy ID                */
    enum PacketDestType dest;            /* Packet destination type  */
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
    union {
        u16 src;                        /* Source port              */
        u16 dest;                       /* Destination port         */
    } port;
    enum TargetType target;               /* Rule                     */
    struct list_head list;
} policy_t;

policy_t* find_policy(int id, enum PacketDestType dest, const char* in, const char* out, const u8* sha,
                      const char* pro, u32 sip, u32 dip, u16 sport, u16 dport, enum TargetType target);

void create_policy(char* pol);

void parse_policy(policy_t* p, char* pol);

void delete_policy(int id, enum PacketDestType dest, const char* in, const char* out, const u8* sha,
                   const char* pro, u32 sip, u32 dip, u16 sport, u16 dport, enum TargetType target);

void clean_policy_table(void);

#define parse_query(q, s) parse_policy(q, s)

#endif //HELLFIRE_POLICY_TABLE_H
