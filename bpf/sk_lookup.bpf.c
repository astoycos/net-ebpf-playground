#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#define bpf_htonl(x) (x)
#else
#error "__BYTE_ORDER__ error"
#endif

//* Dispatcher program for the echo service */
SEC("sk_lookup")
int echo_dispatch(struct bpf_sk_lookup *ctx)
{

    const char err_str[] = "Hello, world, from BPF! Saw socket connect attempt With IP\
    : %x and port: %x \n";

    bpf_trace_printk(err_str, sizeof(err_str), ctx->local_ip4, ctx->local_port);

    struct bpf_sock_tuple out = { 
        .ipv4.saddr = bpf_htonl(0x00000000), 
        .ipv4.sport = bpf_htons(0x0050), 
    };

    struct bpf_sock *redir_sock = bpf_sk_lookup_tcp(ctx, &out, sizeof(out.ipv4), 2, 0); 

    const char err_str2[] = "Hello, world, from BPF! Redirecting socket connect attempt to\
    : %x and port: %x \n";

    bpf_trace_printk(err_str2, sizeof(err_str2), redir_sock->src_ip4, redir_sock->src_port);

    return SK_PASS;
}