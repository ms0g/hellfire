#ifndef HELLFIRE_LOGGER_H
#define HELLFIRE_LOGGER_H

#include "policy_table.h"

void log_info(enum packet_dest_t dest, const char* in, const char* out, const u8* smac, const u8* dmac,
        u8 pro, size_t len, u8 tos, u8 ttl, u32 sip, u32 dip, u16 sport, u16 dport);

#endif //HELLFIRE_LOGGER_H
