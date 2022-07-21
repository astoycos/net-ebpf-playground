/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "socket_proxy.bpf.h"

char _license[] SEC("license") = "GPL";

// SEC("sockops")
// int bpf_sockops_sctp_load(struct bpf_sock_ops *skops)
// {   
//     // Only Care about socket create events
// 	//if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB) { 
        
//     struct svc_backend *backend;

//     struct svc_vip key = {
//         .address = skops->remote_ip4, 
//         .dport = skops->remote_port,
//     }; 

//     const char err_str[] = "Hello, world, from BPF! Saw all Socket With VIP\
//     : %x and port: %x \n";

//     bpf_trace_printk(err_str, sizeof(err_str), skops->remote_ip4, skops->remote_port);

//     // Ignore if we socket dst ip/port isn't a svc
//     backend = bpf_map_lookup_elem(&svc_map, &key);
//     if (!backend) {
//         return 0;
//     }

//     // Load into socket map
//     // insert the source socket in the sock_ops_map
//     int ret = bpf_sock_hash_update(skops, &sctp_socket_map, &key, BPF_NOEXIST);
//     if (ret != 0) {
//         const char err_str[] = "Hello, world, from BPF! Failed to Load Socket\
//         for VIP: %x with port: %x \n";

//         bpf_trace_printk(err_str, sizeof(err_str), skops->remote_ip4, skops->remote_port);
//     }

// 	return 0;
// }

SEC("cgroup/sock")
int bpf_sockops_sctp_load(struct bpf_sock_ops *skops)
{   
    // Only Care about socket create events
	//if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB) { 
        
    struct svc_backend *backend;

    struct svc_vip key = {
        .address = skops->remote_ip4, 
        .dport = skops->remote_port,
    }; 

    const char err_str[] = "Hello, world, from BPF! Saw all Socket With VIP\
    : %x and port: %x \n";

    bpf_trace_printk(err_str, sizeof(err_str), skops->remote_ip4, skops->remote_port);

    // Ignore if we socket dst ip/port isn't a svc
    backend = bpf_map_lookup_elem(&svc_map, &key);
    if (!backend) {
        return 0;
    }

    // Load into socket map
    // insert the source socket in the sock_ops_map
    int ret = bpf_sock_hash_update(skops, &sctp_socket_map, &key, BPF_NOEXIST);
    if (ret != 0) {
        const char err_str[] = "Hello, world, from BPF! Failed to Load Socket\
        for VIP: %x with port: %x \n";

        bpf_trace_printk(err_str, sizeof(err_str), skops->remote_ip4, skops->remote_port);
    }

	return 0;
}

// SEC("cgroup/getsockopt")
// int _getsockopt(struct bpf_sockopt *ctx)
// {




// }