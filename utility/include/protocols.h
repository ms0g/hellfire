#pragma once

#include <unordered_map>
#include <string_view>

namespace Hf::Utility {

enum class ProtType {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    SCTP = 132,
    UNKNOWN = 0
};

ProtType protPton(std::string_view p);

std::string_view protNtop(ProtType p);

}
