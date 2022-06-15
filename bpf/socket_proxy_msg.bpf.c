/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "socket_proxy.bpf.h"

// SEC("sk_msg")
// int bpf_sctp_redirect(struct sk_msg_md *msg)
// {   

//     struct svc_backend *backend;
    
//     struct svc_vip key = {
//         .address = msg->remote_ip4, 
//         .dport = msg->remote_port,
//     };

//     // Ignore if we socket dst ip/port isn't a svc
//     backend = bpf_map_lookup_elem(&svc_map, &key);
//     if (!backend) {
//         return SK_PASS;
//     }

//     bpf_msg_push_data(msg,)
//     msg->remote_ip4 = backend->address;

//     bpf_msg_redirect_hash(msg, &sctp_socket_map, &key, BPF_F_INGRESS);

//     return SK_PASS;
// }

SEC("sk_skb")
int bpf_sctp_redirect(struct __sk_buff *skb)
{   

    struct svc_backend *backend;
    
    struct svc_vip key = {
        .address = skb->remote_ip4, 
        .dport = skb->remote_port,
    };

    // Ignore if we socket dst ip/port isn't a svc
    backend = bpf_map_lookup_elem(&svc_map, &key);
    if (!backend) {
        return SK_PASS;
    }

    //int ret = bpf_skb_proto_xlat(skb, proto);

    // skb->remote_ip4 = backend->address;

    __u32 dstAddr; 
    int ret; 

    ret = bpf_skb_load_bytes_relative(&skb,136,&dstAddr, 32, BPF_HDR_START_NET);
        
    const char err_str[] = "Hello, world, from sk_buff BPF! Got Packet Data\
    for skb Remote addr from __sk_buff: %x remote address from raw packet:%x";

    bpf_trace_printk(err_str, sizeof(err_str), skb->remote_ip4, dstAddr);
    // bpf_sk_redirect_hash(skb, &sctp_socket_map, &key, BPF_F_INGRESS);

    return SK_PASS;
}


