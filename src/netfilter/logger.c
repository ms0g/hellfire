#include "logger.h"
#include "protocols.h"

static char* log_tmp = "hellfire-Dropped: %s IN:%s OUT:%s SRC:%s DST:%s PROTO:%s LEN:%u TOS:0x%08x TTL:%u SPT:%d DPT:%d\n";
static char buf[200];

void log_info(enum packet_dest_t dest, const char* in, const char* out, u8 pro, size_t len,
        u8 tos, u8 ttl, u32 sip, u32 dip, u16 sport, u16 dport) {
    char src[16];
    char dst[16];

    snprintf(src, 16, "%pI4", &sip);
    snprintf(dst, 16, "%pI4", &dip);

    switch (dest) {
        case INPUT:
            snprintf(buf, 200, log_tmp, "INBOUND", in, "", src, dst, prot_ntop(pro), len, tos, ttl, sport, dport);
            break;
        case OUTPUT:
            snprintf(buf, 200, log_tmp, "OUTBOUND", "", out, src, dst, prot_ntop(pro), len, tos, ttl, sport, dport);
            break;

    }
    printk(KERN_INFO "%s", buf);
}