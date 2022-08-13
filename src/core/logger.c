#include "logger.h"
#include "protocols.h"

static char* log_tmp = "hellfire-Dropped: %s IN:%s OUT:%s MAC:%s:%s SRC:%s DST:%s PROTO:%s LEN:%u TOS:0x%08x "
                       "TTL:%u SPT:%d DPT:%d\n";
static char buf[200];

void log_info(enum PacketDestType dest, const char* in, const char* out, const u8* smac, const u8* dmac,
              u8 pro, size_t len, u8 tos, u8 ttl, u32 sip, u32 dip, u16 sport, u16 dport) {
    char srcip[16] = {0}, dstip[16] = {0};
    char srcmac[18] = {0}, dstmac[18] ={0};

    snprintf(srcip, sizeof(srcip), "%pI4", &sip);
    snprintf(dstip, sizeof(dstip), "%pI4", &dip);

    if (smac)
        snprintf(srcmac, sizeof(srcmac), "%pM", smac);

    if (dmac)
        snprintf(dstmac, sizeof(dstmac), "%pM", dmac);

    switch (dest) {
        case INPUT:
            snprintf(buf, 200, log_tmp, "INBOUND", in, "", srcmac, dstmac, srcip, dstip, prot_ntop(pro),
                     len, tos, ttl, sport, dport);
            break;
        case OUTPUT:
            snprintf(buf, 200, log_tmp, "OUTBOUND", "", out, srcmac, dstmac, srcip, dstip, prot_ntop(pro),
                     len, tos, ttl, sport, dport);
            break;

    }
    printk(KERN_INFO "%s", buf);
}