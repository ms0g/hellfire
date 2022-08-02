#ifndef HELLFIRE_PROTOCOLS_H
#define HELLFIRE_PROTOCOLS_H

#include <linux/types.h>

struct proto_kv {
    u8 pro;
    char* str;
};

const char* prot_ntop(u8 pro);

#endif //HELLFIRE_PROTOCOLS_H
