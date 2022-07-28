/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

SEC("sockops")
int load_sock(struct bpf_sock_ops *skops)
{       
    
    const char err_str[] = "Hello, world, from BPF! Saw all Socket With local addr\
    : %x and remote port: %x and local port %x \n";

    if (skops->local_port == 0x1f40 && skops->remote_port == 0) {//|| skops->local_ip4 == bpf_htonl(0xc0a87a5b)) { 

        struct socket_key key = {
            .src_ip = skops->local_ip4,//bpf_htonl(0x00000000), 
            .src_port = bpf_htons(skops->local_port),//bpf_htons(0x0050), 
            .dst_ip = skops->remote_ip4,
            .dst_port = skops->remote_port,
        };

        // insert the source socket in the sock_ops_map
        int ret = bpf_sock_map_update(skops, &socket_map, &key, BPF_NOEXIST);
        if (ret != 0) {
            const char err_str[] = "Failed\n";

            bpf_trace_printk(err_str, sizeof(err_str));
        }

        bpf_trace_printk(err_str, sizeof(err_str), skops->local_ip4, skops->remote_port, skops->local_port);

    }

	return 0;
}