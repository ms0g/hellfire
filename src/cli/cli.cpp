#include <iostream>
#include <cstring>
#include <sstream>
#include "utils.h"
#include "ioc.h"

#define VERSION_MAJOR 0
#define VERSION_MINOR 1
#define VERSION_MICRO 0

#define STRINGIFY0(s) # s
#define STRINGIFY(s) STRINGIFY0(s)
#define VERSION STRINGIFY(VERSION_MAJOR) "." STRINGIFY(VERSION_MINOR) "." STRINGIFY(VERSION_MICRO)

enum class command_t {
    APPEND,
    DELETE,
    LIST,
    FLUSH
};

int main(int argc, char** argv) {
    static const char* usage = "Usage: sudo hellfire [ -<flag> [<val>] | --<name> [<val>] ]...\n\n   "
                               "start                       Start firewall\n   "
                               "stop                        Stop firewall\n   "
                               "-A, --append                Append policy[INPUT/OUTPUT]\n   "
                               "-D, --delete                Delete policy[INPUT/OUTPUT]\n   "
                               "-L, --list                  List policies[INPUT/OUTPUT]\n   "
                               "-F, --flush                 Delete all policies[all]\n   "
                               "-i, --in-interface          Name of an interface via which a packet was received (only for packets entering the INPUT)\n   "
                               "-o, --out-interface         Name of an interface via which a packet is going to be sent (only for packets entering OUTPUT)\n   "
                               "-p, --protocol              The protocol of the rule or of the packet to check\n   "
                               "-s, --src-ip                Source ip address(only for packets entering the INPUT)\n   "
                               "    --src-port              Source port address(only with -p option[TCP/UDP])\n   "
                               "-d  --dst-ip                Destination ip address(only for packets entering OUTPUT)\n   "
                               "    --dst-port              Destination port address(only with -p option[TCP/UDP])\n   "
                               "-t, --target                A firewall rule specifies criteria for a packet[ACCEPT/DROP]\n   "
                               "-h, --help                  Display usage information and exit\n   "
                               "-v, --version               Display version information and exit\n   ";

    command_t cmd;
    // Policy Format: DEST_IF_PRO_IP_PORT_TARGET
    std::stringstream ss;

    if (argc < 3) {
        if (argc == 2 && (!std::strcmp(argv[1], "-h") || !std::strcmp(argv[1], "--help"))) {
            std::cout << usage << std::endl;
        } else if (argc == 2 && (!std::strcmp(argv[1], "-v") || !std::strcmp(argv[1], "--version"))) {
            std::cout << "hellfire version " << VERSION << std::endl;
        } else if (argc == 2 && !std::strcmp(argv[1], "start")) {
            system("sh hellfire_load");
        } else if (argc == 2 && !std::strcmp(argv[1], "stop")) {
            system("sh hellfire_unload");
        } else {
            std::cout << usage << std::endl;
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "-A") || !std::strcmp(argv[i], "--append")) {
            cmd = command_t::APPEND;
            ss << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-D") || !std::strcmp(argv[i], "--delete")) {
            cmd = command_t::DELETE;
            ss << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-L") || !std::strcmp(argv[i], "--list")) {
            cmd = command_t::LIST;
            ss << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-F") || !std::strcmp(argv[i], "--flush")) {
            cmd = command_t::FLUSH;
        } else if (!std::strcmp(argv[i], "-n") || !std::strcmp(argv[i], "--num")) {
            ss << "n" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-i") || !std::strcmp(argv[i], "--in-interface")) {
            ss << "i" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-o") || !std::strcmp(argv[i], "--out-interface")) {
            ss << "o" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-p") || !std::strcmp(argv[i], "--protocol")) {
            ss << "p" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-s") || !std::strcmp(argv[i], "--src-ip")) {
            ss << "si" << inet_bf(argv[++i]) << ".";
        } else if (!std::strcmp(argv[i], "-d") || !std::strcmp(argv[i], "--dst-ip")) {
            ss << "di" << inet_bf(argv[++i]) << ".";
        } else if (!std::strcmp(argv[i], "--src-port")) {
            ss << "sp" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "--dst-port")) {
            ss << "dp" << argv[++i] << ".";
        } else if (!std::strcmp(argv[i], "-t") || !std::strcmp(argv[i], "--target")) {
            ss << "t" << argv[++i];
        }
    }

    IOCDevice iocdev{};
    switch (cmd) {
        case command_t::APPEND: {
            iocdev.sendTo(ss.str());
            break;
        }
        case command_t::DELETE: {
            iocdev.del(ss.str());
            break;
        }
        case command_t::LIST: {
            iocdev.read(ss.str());
            break;
        }
        case command_t::FLUSH:
            iocdev.flush();
            break;
    }
    return 0;
}
