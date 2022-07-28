/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

SEC("sk_skb/stream_parser")
int skb_prog1(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int skb_prog2(struct __sk_buff *skb)
{      

    const char err_str[] = "Saw socket skb redirect on socket with local IP\
    : %x and local port: %x remote port %x\n";

    bpf_trace_printk(err_str, sizeof(err_str), skb->local_ip4, skb->local_port, bpf_ntohs(skb->remote_port));
    
    // struct svc_vip key = {
    //     .address = msg->remote_ip4, 
    //     .dport = msg->remote_port,
    // };

    // Redirect to only server socket
    // struct socket_key key = { 
    //     .src_ip = 0x00000000, 
    //     // Port 8000
    //     //.src_port = bpf_htons(0x1f40),
    //     .src_port = bpf_dhtons(0x2255),
    //     .dst_ip = 0x00000000,
    //     .dst_port = 0x0000,
    // };
    __u32 idx = 1;
    int ret = bpf_sk_redirect_map(skb, &socket_map, idx, BPF_F_INGRESS);
    if (ret == 0) {
        const char err_str3[] = "Failed to direct to Socket\
        ret %d \n";
        
        bpf_trace_printk(err_str3, sizeof(err_str3), ret);
    }

    return ret;
}
