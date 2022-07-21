#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

//* Dispatcher program for the echo service */
SEC("sk_lookup")
int echo_dispatch(struct bpf_sk_lookup *ctx)
{
    const __u32 zero = 0;
	struct bpf_sock *sk;

    const char err_str[] = "Saw socket connect attempt With IP\
    : %x and port: %x \n";

    bpf_trace_printk(err_str, sizeof(err_str), ctx->local_ip4, ctx->local_port);
    
    // Only deal with lookups to port 8789
    if (ctx->local_port != 0x2255) { 
        return SK_PASS;
    }

    struct socket_key key = { 
        .src_ip = 0x00000000, 
        // Port 8000
        .src_port = bpf_htons(0x1f40),
        .dst_ip = 0x00000000,
        .dst_port = 0x0000,
    };

    const char err_str4[] = "Failed To lookup Socket\
        : %x and port: %x \n";

    sk = bpf_map_lookup_elem(&socket_map, &key);
    if (!sk) {
        bpf_trace_printk(err_str4, sizeof(err_str4), key.src_ip, key.src_port);
        return SK_PASS;
    }

    const char err_str2[] = "Redirecting socket connect attempt to\
    : %x and port: %x \n";

    bpf_trace_printk(err_str2, sizeof(err_str2), sk->src_ip4, sk->src_port);

    int ret = bpf_sk_assign(ctx, sk, 0);
    if (ret != 0) {
        const char err_str3[] = "Failed to assign Socket\
        ret %d \n";

        bpf_trace_printk(err_str3, sizeof(err_str3), ret);
    }

    bpf_sk_release(sk);

    return SK_PASS;
}