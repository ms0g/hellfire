#ifndef HELLFIRE_POLICY_TABLE_H
#define HELLFIRE_POLICY_TABLE_H

#include <linux/list.h>
#include "macros.h"

enum packet_dest_t {
    INPUT,
    OUTPUT
};

enum target_t {
    ACCEPT,
    DROP
};

typedef struct {
    int id;                             /* Policy ID                */
    enum packet_dest_t dest;            /* Packet destination type  */
    union {
        char* in;                       /* Ingress interface        */
        char* out;                      /* Egress interface         */
    } interface;
    char* pro;                          /* Protocol                 */
    union {
        u32 src;                        /* Source IP address        */
        u32 dest;                       /* Destination IP address   */
    } ipaddr;
    union {
        u16 src;                        /* Source port              */
        u16 dest;                       /* Destination port         */
    } port;
    enum target_t target;               /* Rule                     */
    struct list_head list;
} policy_t;

policy_t* find_policy(int id, enum packet_dest_t dest, char* in, char* out, char* pro,
                      u32 sip, u32 dip, u16 sport, u16 dport, enum target_t target);

void create_policy(char* pol);

void policy_parse(policy_t* p, char* pol);

void delete_policy(int id, enum packet_dest_t dest, char* in, char* out, char* pro,
                   u32 sip, u32 dip, u16 sport, u16 dport, enum target_t target);

void clean_policy_table(void);

EXPORT_TYPE_AS(policy_t, query_t)
#define query_parse(q, s) policy_parse(q, s)

#endif //HELLFIRE_POLICY_TABLE_H
