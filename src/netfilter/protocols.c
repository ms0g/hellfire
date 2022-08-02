#include "protocols.h"
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

const struct proto_kv _kv[] = {
        {IPPROTO_ICMP, "icmp"},
        {IPPROTO_UDP, "udp"},
        {IPPROTO_TCP, "tcp"}
};

#define PROTO_COUNT (int)(sizeof(_kv)/sizeof(_kv[0]))

const char* prot_ntop(u8 pro) {
    for (int i = 0; i < PROTO_COUNT; ++i) {
        if (_kv[i].pro == pro)
            return _kv[i].str;
    }
    return NULL;
}
