# hellfire
Hellfire is a toy linux firewall based on [Netfilter](https://www.netfilter.org "The netfilter.org project") which filters TCP/UDP/ICMP packets according to user-specified rules.

Hellfire is composed of an user-space program `hellfire` that is a cli tool and a kernel-space module
`hellfire_core`. Communications between user space and kernel space are done by means of
the device file `/dev/hellfire` using `ioctl` and `write` syscall.Using `hellfire`, user can specify filtering rules
that include some of the following fields:
+ Direction: inbound, outbound
+ Interface: inbound, outbound
+ Source: ip address, port number
+ Destination: ip address, port number
+ Protocol: tcp, udp, icmp

Each created rule is sent to `hellfire_core` module.The module inserts a new entry
into the policy table to compare every packets with user-specified rules. 
When the fields of the packet match one of the rules, the packet is dropped.

Built with kernel 4.4.0-210-generic on Ubuntu 16.04.7 LTS
### Prerequisites
+ [CMake](http://www.cmake.org "CMake project page") (>= 3.20)
+ [g++](https://gcc.gnu.org "GCC, the GNU Compiler Collection") (>=7.5.0)

### Building
```bash
cd build
./builder.sh
```

### Usage
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
Usage:  curser [ -<flag> [<val>] | --<name> [<val>] ]...

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
       --src-port              Source port address(only with -p option[TCP/UDP])
   -d  --dst-ip                Destination ip address(only for packets entering OUTPUT)
       --dst-port              Destination port address(only with -p option[TCP/UDP])
   -t, --target                A firewall rule specifies criteria for a packet[ACCEPT/DROP]
   -h, --help                  Display usage information and exit
   -v, --version               Display version information and exit
```
