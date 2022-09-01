#include <iostream>
#include <cstring>
#include <sstream>
#include <vector>
#include <cstdlib>
#include "utils.h"
#include "ioc.h"

#define VERSION_MAJOR 0
#define VERSION_MINOR 2
#define VERSION_PATCH 2

#define STRINGIFY0(s) # s
#define STRINGIFY(s) STRINGIFY0(s)
#define VERSION STRINGIFY(VERSION_MAJOR) "." STRINGIFY(VERSION_MINOR) "." STRINGIFY(VERSION_PATCH)

namespace Hf {

enum class Command {
    APPEND,
    DELETE,
    LIST,
    FLUSH
};
}
int main(int argc, char** argv) {
    static const char* usage = "Usage: sudo hellfire [ -<flag> [<val>] | --<name> [<val>] ]...\n\n   "
                               "start                       Start firewall\n   "
                               "stop                        Stop firewall\n   "
                               "-A, --append                Append policy[INPUT/OUTPUT]\n   "
                               "-D, --delete                Delete policy[INPUT/OUTPUT]\n   "
                               "-L, --list                  List policies[INPUT/OUTPUT]\n   "
                               "-F, --flush                 Delete all policies[all]\n   "
                               "-n, --num                   Policy id(only with -L and -D option)\n   "
                               "-i, --in-interface          Name of an interface via which a packet was received (only for packets entering the INPUT)\n   "
                               "-o, --out-interface         Name of an interface via which a packet is going to be sent (only for packets entering OUTPUT)\n   "
                               "    --src-mac               Source mac address(only for packets entering the INPUT)\n   "
                               "-p, --protocol              The protocol of the rule or of the packet to check[tcp/udp/sctp/icmp)\n   "
                               "-s, --src-ip                Source ip address(only for packets entering the INPUT)\n   "
                               "    --src-ip-range          Source ip address range[ip:ip](only for packets entering the INPUT)\n   "
                               "    --src-port              Source port address(only with -p option)\n   "
                               "-d  --dst-ip                Destination ip address(only for packets entering OUTPUT)\n   "
                               "    --dst-ip-range          Destination ip address range[ip:ip](only for packets entering the OUTPUT)\n   "
                               "    --dst-port              Destination port address(only with -p option)\n   "
                               "-t, --target                A firewall rule specifies criteria for a packet[ACCEPT/DROP]\n   "
                               "-h, --help                  Display usage information and exit\n   "
                               "-v, --version               Display version information and exit\n   ";

    Hf::Command cmd;
    // Policy Format: DEST_IF_PRO_IP_PORT_TARGET
    std::stringstream ss;
    std::vector<std::string> bulk_policies;

    if (argc < 3) {
        if (argc == 2 && (!std::strcmp(argv[1], "-h") || !std::strcmp(argv[1], "--help"))) {
            std::cout << "hellfire version " << VERSION << "\n" << usage << std::endl;
        } else if (argc == 2 && (!std::strcmp(argv[1], "-v") || !std::strcmp(argv[1], "--version"))) {
            std::cout << "hellfire version " << VERSION << std::endl;
        } else if (argc == 2 && !std::strcmp(argv[1], "start")) {
            if (std::system("sh hellfire_load") != 0) {
                std::cerr << "hellfire: Error when starting" << std::endl;
            }
        } else if (argc == 2 && !std::strcmp(argv[1], "stop")) {
            if (std::system("sh hellfire_unload") != 0) {
                std::cerr << "hellfire: Error when stopping" << std::endl;
            }
        } else {
            std::cout << "hellfire version " << VERSION << "\n" << usage << std::endl;
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "-A") || !std::strcmp(argv[i], "--append")) {
            cmd = Hf::Command::APPEND;
            ss << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-D") || !std::strcmp(argv[i], "--delete")) {
            cmd = Hf::Command::DELETE;
            ss << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-L") || !std::strcmp(argv[i], "--list")) {
            cmd = Hf::Command::LIST;
            ss << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-F") || !std::strcmp(argv[i], "--flush")) {
            cmd = Hf::Command::FLUSH;
        } else if (!std::strcmp(argv[i], "-n") || !std::strcmp(argv[i], "--num")) {
            ss << "n" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-i") || !std::strcmp(argv[i], "--in-interface")) {
            if (!bulk_policies.empty()) {
                auto arg = std::string_view{argv[++i]};
                for (auto& p: bulk_policies) {
                    p.append("i").append(arg).append(".");
                }
            } else
                ss << "i" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-o") || !std::strcmp(argv[i], "--out-interface")) {
            if (!bulk_policies.empty()) {
                auto arg = std::string_view{argv[++i]};
                for (auto& p: bulk_policies) {
                    p.append("o").append(arg).append(".");
                }
            } else
                ss << "o" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "--src-mac")) {
            ss << "sm" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-p") || !std::strcmp(argv[i], "--protocol")) {
            if (!bulk_policies.empty()) {
                auto arg = std::string_view{argv[++i]};
                for (auto& p: bulk_policies) {
                    p.append("p").append(arg).append(".");
                }
            } else
                ss << "p" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-s") || !std::strcmp(argv[i], "--src-ip")) {
            ss << "si" << Hf::inet_bf(argv[++i]) << ".";
        } else if (!std::strcmp(argv[i], "--src-ip-range")) {
            auto s = std::string{argv[++i]};
            auto pos = s.find(':');
            auto first_ip = s.substr(0, pos);
            auto last_ip = s.substr(pos + 1);
            auto pol = ss.str();
            auto temp = pol;
            for (uint32_t ip = Hf::inet_bf(first_ip.c_str()); ip <= Hf::inet_bf(last_ip.c_str()); ++ip) {
                temp.append("si").append(std::to_string(ip)).append(".");
                bulk_policies.emplace_back(temp);
                temp.clear();
                temp = pol;
            }
        } else if (!std::strcmp(argv[i], "-d") || !std::strcmp(argv[i], "--dst-ip")) {
            ss << "di" << Hf::inet_bf(argv[++i]) << ".";
        } else if (!std::strcmp(argv[i], "--dst-ip-range")) {
            auto s = std::string{argv[++i]};
            auto pos = s.find(':');
            auto first_ip = s.substr(0, pos);
            auto last_ip = s.substr(pos + 1);
            auto pol = ss.str();
            auto temp = pol;
            for (uint32_t ip = Hf::inet_bf(first_ip.c_str()); ip <= Hf::inet_bf(last_ip.c_str()); ++ip) {
                temp.append("di").append(std::to_string(ip)).append(".");
                bulk_policies.emplace_back(temp);
                temp.clear();
                temp = pol;
            }
        } else if (!std::strcmp(argv[i], "--src-port")) {
            if (!bulk_policies.empty()) {
                auto arg = std::string_view{argv[++i]};
                for (auto& p: bulk_policies) {
                    p.append("sp").append(arg).append(".");
                }
            } else
                ss << "sp" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "--dst-port")) {
            if (!bulk_policies.empty()) {
                auto arg = std::string_view{argv[++i]};
                for (auto& p: bulk_policies) {
                    p.append("dp").append(arg).append(".");
                }
            } else
                ss << "dp" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-t") || !std::strcmp(argv[i], "--target")) {
            if (!bulk_policies.empty()) {
                auto arg = std::string_view{argv[++i]};
                for (auto& p: bulk_policies) {
                    p.append("t").append(arg);
                }
            } else
                ss << "t" << argv[++i];
        }
    }

    Hf::IOCDevice iocdev{};
    switch (cmd) {
        case Hf::Command::APPEND: {
            bulk_policies.empty() ? iocdev.write(ss.str()) : iocdev.bulkWrite(bulk_policies);
            break;
        }
        case Hf::Command::DELETE: {
            iocdev.del(ss.str());
            break;
        }
        case Hf::Command::LIST: {
            iocdev.list(ss.str());
            break;
        }
        case Hf::Command::FLUSH:
            iocdev.flush();
            break;
    }
    return 0;
}
