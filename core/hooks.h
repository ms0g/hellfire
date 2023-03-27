#ifndef HELLFIRE_HOOKS_H
#define HELLFIRE_HOOKS_H

#include <linux/netfilter_ipv4.h>

unsigned int hfIpIngressHook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);

unsigned int hfIpEgressHook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);

#endif //HELLFIRE_HOOKS_H
