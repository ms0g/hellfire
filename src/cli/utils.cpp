#include "utils.h"
#include <arpa/inet.h> //inet_pton
#include <cstdlib>
#include <cstdio>

uint32_t inet_bf(const char* addr) {
    struct sockaddr_in sa{};

    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        perror("inet binary formatting failed");
        exit(EXIT_FAILURE);
    }

    return ntohl(sa.sin_addr.s_addr);
}