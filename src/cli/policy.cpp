#include "policy.h"
#include <iostream>
#include <cstring>
#include "ip.h"

namespace Hf {

Policy::Policy(std::string_view pol) {
    std::string_view token;
    char* svp = const_cast<char*>(pol.data());

    while (svp != nullptr) {
        token = strsep(&svp, ".");
        if (token == "null") {
            continue;
        } else if (token.starts_with("id")) {
            id = std::stoi(&token[2]);
        } else if (token.starts_with("dp")) {
            port.dest = std::stoi(&token[2]);
        } else if (token.starts_with("sp")) {
            port.src = std::stoi(&token[2]);
        } else if (token.starts_with("si")) {
            ipaddr.src = std::stoul(&token[2]);
        } else if (token.starts_with("di")) {
            ipaddr.dest = std::stoul(&token[2]);
        } else if (token.starts_with("sm")) {
            mac.src = std::string{&token[2]};
        } else if (token.starts_with('d')) {
            dest = static_cast<DestType>(std::stoi(&token[1]));
        } else if (token.starts_with('i')) {
            interface.in = std::string{&token[1]};
        } else if (token.starts_with('o')) {
            interface.out = std::string{&token[1]};
        } else if (token.starts_with('p')) {
            pro = std::string{&token[1]};
        } else if (token.starts_with('t')) {
            target = static_cast<TargetType>(std::stoi(&token[1]));
        }
    }
}

std::ostream& operator<<(std::ostream& os, const Policy& pol) {
    os << "ID:" << pol.id;

    switch (pol.dest) {
        case Policy::DestType::INPUT:
            os << " DEST:INPUT";
            os << " IFN:" << pol.interface.in;
            os << " MAC:" << pol.mac.src;
            os << " SRC:" << Hf::Utility::Ip::inet_pf(pol.ipaddr.src);
            os << " DPT:" << pol.port.dest;
            break;
        case Policy::DestType::OUTPUT:
            os << " DEST:OUTPUT";
            os << " IFN:" << pol.interface.out;
            os << " DST:" << Hf::Utility::Ip::inet_pf(pol.ipaddr.dest);
            os << (pol.port.src ? " SPT:" : " DPT:") << (pol.port.src ? pol.port.src : pol.port.dest);
            break;
    }

    os << " PRO:" << pol.pro;
    os << " TGT:" << (pol.target == Policy::TargetType::DROP ? "DROP" : "ACCEPT");

    return os;
}

}//namespace Hf