#include "hooks.h"
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include "policy_table.h"
#include "logger.h"


unsigned int hfIpIngressHook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    const struct ethhdr* eth;
    const struct iphdr* iph;
    const struct udphdr* udp;
    const struct tcphdr* tcp;
    const struct sctphdr* sctp;
    const struct net_device* dev;
    const HfPolicy* pol;
    u32 sip;
    u16 sport=0, dport=0;
    u8 sha[ETH_ALEN], tha[ETH_ALEN];

    if (unlikely(!skb))
        return NF_DROP;

    dev = skb->dev;

    eth = eth_hdr(skb);
    memcpy(sha, eth->h_source, ETH_ALEN);
    memcpy(tha, eth->h_dest, ETH_ALEN);

    iph = ip_hdr(skb);
    sip = ntohl(iph->saddr);
    switch (iph->protocol) {
        case IPPROTO_ICMP:
            pol = hfFindPolicy(0, INPUT, dev->name, NULL, sha, "icmp", sip, 0, 0, 0, 0);
            break;
        case IPPROTO_UDP:
            udp = udp_hdr(skb);
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);

            pol = hfFindPolicy(0, INPUT, dev->name, NULL, sha, "udp", sip, 0, sport, dport, 0);
            break;
        case IPPROTO_TCP:
            tcp = tcp_hdr(skb);
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);

            pol = hfFindPolicy(0, INPUT, dev->name, NULL, sha, "tcp", sip, 0, sport, dport, 0);
            break;
        case IPPROTO_SCTP:
            sctp = sctp_hdr(skb);
            sport = ntohs(sctp->source);
            dport = ntohs(sctp->dest);

            pol = hfFindPolicy(0, INPUT, dev->name, NULL, sha, "sctp", sip, 0, sport, dport, 0);
            break;
    }

    if (pol) {
        if (pol->target == DROP) {
            hfLogInfo(INPUT, dev->name, NULL, sha, tha, iph->protocol, ntohs(iph->tot_len),
                      iph->tos, iph->ttl, iph->saddr, iph->daddr, sport, dport);
            return NF_DROP;
        } else
            return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

unsigned int hfIpEgressHook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    const struct iphdr* iph;
    const struct udphdr* udp;
    const struct tcphdr* tcp;
    const struct sctphdr* sctp;
    const struct net_device* dev;
    const HfPolicy* pol;
    u32 dip;
    u16 sport=0, dport=0;

    if (unlikely(!skb))
        return NF_DROP;

    dev = skb->dev;

    iph = ip_hdr(skb);
    dip = ntohl(iph->daddr);
    switch (iph->protocol) {
        case IPPROTO_ICMP:
            pol = hfFindPolicy(0, OUTPUT, NULL, dev->name, NULL, "icmp", 0, dip, 0, 0, 0);
            break;
        case IPPROTO_UDP:
            udp = udp_hdr(skb);
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);

            pol = hfFindPolicy(0, OUTPUT, NULL, dev->name, NULL, "udp", 0, dip, sport, dport, 0);
            break;
        case IPPROTO_TCP:
            tcp = tcp_hdr(skb);
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);

            pol = hfFindPolicy(0, OUTPUT, NULL, dev->name, NULL, "tcp", 0, dip, sport, dport, 0);
            break;
        case IPPROTO_SCTP:
            sctp = sctp_hdr(skb);
            sport = ntohs(sctp->source);
            dport = ntohs(sctp->dest);

            pol = hfFindPolicy(0, OUTPUT, NULL, dev->name, NULL, "sctp", 0, dip, sport, dport, 0);
            break;
    }

    if (pol) {
        if (pol->target == DROP) {
            hfLogInfo(OUTPUT, NULL, dev->name, NULL, NULL, iph->protocol, ntohs(iph->tot_len),
                      iph->tos, iph->ttl, iph->saddr, iph->daddr, sport, dport);
            return NF_DROP;
        } else
            return NF_ACCEPT;
    }
    return NF_ACCEPT;
}
