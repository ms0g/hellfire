#include "policy.h"
#include <iostream>
#include <cstring>
#include "utils.h"

Policy::Policy(std::string_view p) {
    std::string_view token;
    char* svp = const_cast<char*>(p.data());

    while (svp != nullptr && !(token = strsep(&svp, ".")).empty()) {
        if (token == "(null)") {
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
        } else if (token.starts_with('d')) {
            dest = static_cast<dest_t>(std::stoi(&token[1]));
        } else if (token.starts_with('i')) {
            interface.in = std::string{&token[1]};
        } else if (token.starts_with('o')) {
            interface.out = std::string{&token[1]};
        } else if (token.starts_with('p')) {
            pro = std::string{&token[1]};
        } else if (token.starts_with('t')) {
            target = static_cast<target_t>(std::stoi(&token[1]));
        }
    }
}

std::ostream& operator<<(std::ostream& os, const Policy& pol) {
    os << "ID:" << pol.id;

    switch (pol.dest) {
        case Policy::dest_t::INPUT:
            os << " DEST:INPUT";
            os << " IFN:" << pol.interface.in;
            os << " SRC:" << inet_pf(pol.ipaddr.src);
            os << " DPT:" << pol.port.dest;
            break;
        case Policy::dest_t::OUTPUT:
            os << " DEST:OUTPUT";
            os << " IFN:" << pol.interface.out;
            os << " DST:" << inet_pf(pol.ipaddr.dest);
            os << " SPT:" << pol.port.src;
            break;
    }

    os << " PRO:" << pol.pro;
    os << " TGT:" << (pol.target == Policy::target_t::DROP ? "DROP" : "ACCEPT");

    return os;
}
