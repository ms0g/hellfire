#include "policy.h"
#include <iostream>
#include "utils.h"

Policy::Policy(std::string_view p) {
    size_t start = 0, end;
    std::string_view token;
    int token_order = 0;

    while ((end = p.find_first_of('.', start)) != std::string_view::npos) {
        token = p.substr(start, end - start);
        if (token == "(null)") {
            goto go_on;
        }
        switch (token_order) {
            case 0:
                id = std::stoi(token.data());
                break;
            case 1:
                dest = static_cast<dest_t>(std::stoi(token.data()));
                break;
            case 2:
                switch (dest) {
                    case dest_t::INPUT:
                        interface.in = std::string{token};
                        break;
                    case dest_t::OUTPUT:
                        interface.out = std::string{token};
                        break;
                }
                break;
            case 3:
                pro = std::string{token};
                break;
            case 4:
                switch (dest) {
                    case dest_t::INPUT:
                        ipaddr.src = std::stoul(token.data());
                        break;
                    case dest_t::OUTPUT:
                        ipaddr.dest = std::stoul(token.data());
                        break;
                }
                break;
            case 5:
                switch (dest) {
                    case dest_t::INPUT:
                        port.dest = std::stoi(token.data());
                        break;
                    case dest_t::OUTPUT:
                        port.src = std::stoi(token.data());
                        break;
                }
                break;
            case 6:
                target = static_cast<target_t>(std::stoi(token.data()));
                break;
        }
go_on:
        start = end + 1;
        ++token_order;
    }
}

std::ostream& operator<<(std::ostream& os, const Policy& pol) {
    os << "ID:" << pol.id;

    switch (pol.dest) {
        case Policy::dest_t::INPUT:
            os << " DEST:INPUT";
            os << " IFN:" << pol.interface.in;
            os << " SRC:" << inet_pf(pol.ipaddr.src);
            os << " DPORT:" << pol.port.dest;
            break;
        case Policy::dest_t::OUTPUT:
            os << " DEST:OUTPUT";
            os << " IFN:" << pol.interface.out;
            os << " DST:" << inet_pf(pol.ipaddr.dest);
            os << " SPORT:" << pol.port.src;
            break;
    }

    os << " PRO:" << pol.pro;
    os << " TGT:" << (pol.target == Policy::target_t::DROP ? "DROP" : "ACCEPT");

    return os;
}
