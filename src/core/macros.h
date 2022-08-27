#ifndef HELLFIRE_MACROS_H
#define HELLFIRE_MACROS_H

#include <linux/string.h>

#define IS_EQUAL(s1, s2) !strcmp(s1, s2)
#define IS_MAC_ADDR_EMPTY(m) (memcmp(m, "\0\0\0\0\0", 6) == 0)

#endif //HELLFIRE_MACROS_H
