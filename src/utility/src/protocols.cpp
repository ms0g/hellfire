#include "protocols.h"

namespace Hf::Utility {

std::unordered_map<std::string_view, ProtType> protMap = {
        {"icmp",   ProtType::ICMP},
        {"tcp",  ProtType::TCP},
        {"udp",  ProtType::UDP},
        {"sctp", ProtType::SCTP}};

ProtType protPton(std::string_view pro) {
    for (const auto& p: protMap) {
        if (pro == p.first)
            return p.second;
    }
    return ProtType::UNKNOWN;
}

std::string_view protNtop(ProtType pro) {
    for (const auto& p: protMap) {
        if (pro == p.second)
            return p.first;
    }
    return "";
}
}
