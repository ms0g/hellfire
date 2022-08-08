#pragma once

#include <string>
#include <string_view>


class Policy {
public:
    explicit Policy(std::string_view p);

    enum class dest_t {
        INPUT,
        OUTPUT
    };

    enum class target_t {
        ACCEPT,
        DROP
    };

    int id{};                           /* Policy ID                */
    dest_t dest;                        /* Packet destination type  */
    struct {
        std::string in;                 /* Ingress interface        */
        std::string out;                /* Egress interface         */
    } interface;
    std::string pro;                    /* Protocol                 */
    struct {
        std::string src;                /* Source MAC Address       */
        std::string dest;               /* Destination MAC Address  */
    } mac;
    union {
        uint32_t src;                   /* Source IP address        */
        uint32_t dest;                  /* Destination IP address   */
    } ipaddr{};
    union {
        uint16_t src;                   /* Source port              */
        uint16_t dest;                  /* Destination port         */
    } port{};
    target_t target{};                  /* Rule                     */

    friend std::ostream& operator<<(std::ostream& os, const Policy& ep);
};
