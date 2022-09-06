#include "protocols.h"
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

struct {
    u8 pro;
    char* str;
} static const prot_kv[] = {
        {IPPROTO_ICMP, "icmp"},
        {IPPROTO_UDP,  "udp"},
        {IPPROTO_TCP,  "tcp"},
        {IPPROTO_SCTP, "sctp"}
};

#define PROTO_COUNT (int)(sizeof(prot_kv)/sizeof(prot_kv[0]))

const char* hfProtNtop(u8 pro) {
    for (int i = 0; i < PROTO_COUNT; ++i) {
        if (prot_kv[i].pro == pro)
            return prot_kv[i].str;
    }
    return NULL;
}
