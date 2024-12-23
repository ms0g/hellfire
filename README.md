# Hellfire: A Linux Toy Firewall based on Netfilter
Hellfire is a lightweight Linux firewall built upon the [Netfilter](https://www.netfilter.org "The netfilter.org project") framework, designed to filter `TCP`, `SCTP`, `UDP`, and `ICMP` packets in accordance with user-defined rules. You can use a command-line tool named `hellfire` to create the rules to control packet flow. Each rule generated is dispatched to the `hellfire_core` module. This kernel module then inserts a new entry into the policy table, enabling the comparison of incoming packets against user-defined rules. In cases where packet attributes correspond to a defined rule, the packet is subsequently dropped.

## Features
Types of filtering rules:

+ `Direction:` Inbound or Outbound
+ `Interface:` Inbound or Outbound
+ `Source:` IP address, IP address range, MAC address, port number
+ `Destination:` IP address, IP address range, port number
+ `Protocol:` TCP, UDP, SCTP, ICMP
  


## Prerequisites
+ [CMake](http://www.cmake.org "CMake project page") (>= 3.20)
+ [g++](https://gcc.gnu.org "GCC, the GNU Compiler Collection") (>=7.5.0)
+ [SQLite3](https://www.sqlite.org, "SQLite project page") (>= 3.43)

## Building
```bash
cd build
./builder.sh
```

## Usage
Start
```bash
➜ sudo ./hellfire start
```
Stop
```bash
➜ sudo ./hellfire stop
```
ADD rules
```bash
➜ sudo ./hellfire -A INPUT -i enp0s8 -s 192.168.56.17 -p icmp -t DROP
➜ sudo ./hellfire -A INPUT -s 192.168.56.17 -p tcp --dst-port 80 -t DROP
➜ sudo ./hellfire -A INPUT --src-mac 08:00:27:27:ee:33 -t DROP
➜ sudo ./hellfire -A INPUT --src-ip-range 192.168.56.17:192.168.56.18 -t DROP
➜ sudo ./hellfire -A OUTPUT -d 192.168.56.17 -p icmp -t DROP
```
LIST rules
```bash
➜ sudo ./hellfire -L INPUT -p icmp
ID:1 DEST:INPUT IFN:(null) SRC:192.168.56.17 DPT:0 PRO:icmp TGT:DROP
```
DELETE rules
```bash
➜ sudo ./hellfire -D INPUT -n 1
```
FLUSH policy table
```bash
➜ sudo ./hellfire -F all
Flushed the policy table
```
Help
```bash
➜ sudo ./hellfire -h
Usage:  hellfire [val | -<flag> [<val>] | --<name> [<val>] ]...

   start                       Start firewall
   stop                        Stop firewall
   -A, --append                Append policy[INPUT/OUTPUT]
   -D, --delete                Delete policy[INPUT/OUTPUT]
   -L, --list                  List policies[INPUT/OUTPUT]
   -F, --flush                 Delete all policies[all]
   -n, --num                   Policy id(only with -L and -D option)
   -i, --in-interface          Name of an interface via which a packet was received (only for packets entering the INPUT)
   -o, --out-interface         Name of an interface via which a packet is going to be sent (only for packets entering OUTPUT)
       --src-mac               Source mac address(only for packets entering the INPUT)
   -p, --protocol              The protocol of the rule or of the packet to check
   -s, --src-ip                Source ip address(only for packets entering the INPUT)
       --src-ip-range          Source ip address range[ip:ip](only for packets entering the INPUT)
       --src-port              Source port address(only with -p option)
   -d  --dst-ip                Destination ip address(only for packets entering OUTPUT)
       --dst-ip-range          Destination ip address range[ip:ip](only for packets entering the OUTPUT)
       --dst-port              Destination port address(only with -p option)
   -t, --target                A firewall rule specifies criteria for a packet[ACCEPT/DROP]
   -h, --help                  Display usage information and exit
   -v, --version               Display version information and exit
```
## Contribution

Contributions are welcome! Feel free to fork this repository, make improvements, and submit pull requests.

## License
Hellfire is licensed under the GPL-2.0 License. See the LICENSE file for details.
