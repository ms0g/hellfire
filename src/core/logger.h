#ifndef HELLFIRE_LOGGER_H
#define HELLFIRE_LOGGER_H

#include <linux/types.h>

enum HfPacketDestType;

void hfLogInfo(enum HfPacketDestType dest, const char* in, const char* out, const u8* smac, const u8* dmac,
               u8 pro, size_t len, u8 tos, u8 ttl, u32 sip, u32 dip, u16 sport, u16 dport);

#endif //HELLFIRE_LOGGER_H
