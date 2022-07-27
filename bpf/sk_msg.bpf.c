/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

SEC("sk_msg")
int msg_redirect(struct sk_msg_md *msg)
{      

    const char err_str[] = "Saw socket sentmsg attempt With IP\
    : %x and local port: %x remote port %x\n";

    bpf_trace_printk(err_str, sizeof(err_str), msg->local_ip4, msg->local_port, msg->remote_port);
    
    // struct svc_vip key = {
    //     .address = msg->remote_ip4, 
    //     .dport = msg->remote_port,
    // };

    // Redirect to only server socket
    struct socket_key key = { 
        .src_ip = 0x00000000, 
        // Port 8000
        .src_port = bpf_htons(0x1f40),
        .dst_ip = 0x00000000,
        .dst_port = 0x0000,
    };

    int ret = bpf_msg_redirect_hash(msg, &socket_map, &key, BPF_F_INGRESS);
    if (ret != 0) {
        const char err_str3[] = "Failed to direct to Socket\
        ret %d \n";

        bpf_trace_printk(err_str3, sizeof(err_str3), ret);
    }

    return SK_PASS;
}
