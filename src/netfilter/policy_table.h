#ifndef HELLFIRE_POLICY_TABLE_H
#define HELLFIRE_POLICY_TABLE_H

#include <linux/list.h>

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

policy_t* check_if_input(policy_t* entry, char* in, char* pro, u32 sip, u16 dport);

policy_t* check_if_output(policy_t* entry, char* out, char* pro, u32 dip, u16 sport);

void create_policy(char* pol);

void delete_policy(int id, enum packet_dest_t dest);

void clean_policy_table(void);

#endif //HELLFIRE_POLICY_TABLE_H
