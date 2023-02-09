/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{   
    struct icmphdr *icmp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
