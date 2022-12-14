#pragma once

#include <string>
#include <string_view>
#include "protocols.h"

namespace Hf {

class Policy {
public:
    explicit Policy(std::string_view pol);

    enum class DestType {
        INPUT,
        OUTPUT
    };

    enum class TargetType {
        ACCEPT,
        DROP
    };

    unsigned int id{};                  /* Policy ID                */
    DestType dest;                      /* Packet destination type  */
    struct {
        std::string in;                 /* Ingress interface        */
        std::string out;                /* Egress interface         */
    } interface;
    Utility::ProtType pro;              /* Protocol                 */
    struct {
        std::string src;                /* Source MAC Address       */
    } mac;
    union {
        uint32_t src;                   /* Source IP address        */
        uint32_t dest;                  /* Destination IP address   */
    } ipaddr{};
    struct {
        uint16_t src;                   /* Source port              */
        uint16_t dest;                  /* Destination port         */
    } port{};
    TargetType target{};                /* Rule                     */

    friend std::ostream& operator<<(std::ostream& os, const Policy& ep);
};

std::string toDestPf(std::string_view n);

std::string toTargetPf(std::string_view n);

} //namespace Hf