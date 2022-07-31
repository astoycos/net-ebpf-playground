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
    : %x and local port: %x\n";

    bpf_trace_printk(err_str, sizeof(err_str), skb->local_ip4, skb->local_port);

    // struct svc_vip key = {
    //     .address = msg->remote_ip4,
    //     .dport = msg->remote_port,
    // };

    //__u32 idx = 1;
    // int ret = 1;

    // get packet to server put on ingress queue of server socket
    if (skb->local_port == 0x2255)
    {

        const char err_str2[] = "redirect to server local ports %x -> %x\n";

        bpf_trace_printk(err_str2, sizeof(err_str2), skb->local_port, 0x1f40);

        struct socket_key key = {
            // 2.10.168.192
            .src_ip = 0x20aa8c0,
            // Port 8000
            .src_port = bpf_htons(0x1f40),
            //.src_port = 0x1f40,
            .dst_ip = 0x00000000,
            .dst_port = 0x0000,
        };

        int ret = bpf_sk_redirect_hash(skb, &socket_map, &key, BPF_F_INGRESS);
        if (ret == 0)
        {
            const char err_str3[] = "Failed to direct to Socket\
            ret %d \n";

            bpf_trace_printk(err_str3, sizeof(err_str3), ret);
        }
    }

    // Get packet pack to client put on egress queue of proxy socket
    if (skb->local_port == 0x1f40)
    {

        const char err_str4[] = "redirect to proxy local ports %x -> %x\n";

        bpf_trace_printk(err_str4, sizeof(err_str4), skb->local_port, 0x2255);

        struct socket_key key = {
            .src_ip = 0x00000000,
            // Port 8000
            //.src_port = bpf_htons(0x1f40),
            .src_port = bpf_htons(0x2255),
            .dst_ip = 0x00000000,
            .dst_port = 0x0000,
        };

        int ret = bpf_sk_redirect_hash(skb, &socket_map, &key, 0);
        if (ret == 0)
        {
            const char err_str3[] = "Failed to direct to Socket\
            ret %d \n";

            bpf_trace_printk(err_str3, sizeof(err_str3), ret);
        }
    }

    return SK_PASS;
}
