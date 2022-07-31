#include "hooks.h"
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include "policy_table.h"

unsigned int ip_ingress_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct udphdr* udp;
    struct tcphdr* tcp;
    struct net_device* dev;
    policy_t* pol;
    u32 sip;
    u16 dport;

    if (unlikely(!skb))
        return NF_DROP;

    dev = skb->dev;

    iph = ip_hdr(skb);
    sip = ntohl(iph->saddr);
    if (iph->protocol == IPPROTO_ICMP) {
        pol = find_policy(0, INPUT, dev->name, NULL, "icmp", sip, 0, 0, 0, 0);
    } else if (iph->protocol == IPPROTO_UDP) {
        udp = udp_hdr(skb);
        dport = ntohs(udp->dest);

        pol = find_policy(0, INPUT, dev->name, NULL, "udp", sip, 0, 0, dport, 0);
    } else if (iph->protocol == IPPROTO_TCP) {
        tcp = tcp_hdr(skb);
        dport = ntohs(tcp->dest);

        pol = find_policy(0, INPUT, dev->name, NULL, "tcp", sip, 0, 0, dport, 0);
    }

    if (pol) {
        if (pol->target == DROP) {
            printk(KERN_INFO "hellfire: 1 Inbound %s packet DROPPED\n", pol->pro);
            return NF_DROP;
        } else
            return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

unsigned int ip_egress_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct udphdr* udp;
    struct tcphdr* tcp;
    struct net_device* dev;
    policy_t* pol;
    u32 dip;
    u16 sport;

    if (unlikely(!skb))
        return NF_DROP;

    dev = skb->dev;

    iph = ip_hdr(skb);
    dip = ntohl(iph->daddr);
    if (iph->protocol == IPPROTO_ICMP) {
        pol = find_policy(0, OUTPUT, NULL, dev->name, "icmp", 0, dip, 0, 0, 0);
    } else if (iph->protocol == IPPROTO_UDP) {
        udp = udp_hdr(skb);
        sport = ntohs(udp->source);

        pol = find_policy(0, OUTPUT, NULL, dev->name, "udp", 0, dip, sport, 0, 0);
    } else if (iph->protocol == IPPROTO_TCP) {
        tcp = tcp_hdr(skb);
        sport = ntohs(tcp->source);

        pol = find_policy(0, OUTPUT, NULL, dev->name, "tcp", 0, dip, sport, 0, 0);
    }

    if (pol) {
        if (pol->target == DROP) {
            printk(KERN_INFO "hellfire: 1 Outbound %s packet DROPPED \n", pol->pro);
            return NF_DROP;
        } else
            return NF_ACCEPT;
    }
    return NF_ACCEPT;
}
