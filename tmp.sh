sudo bpftool prog -d load ./.output/socket_proxy.bpf.o /sys/fs/bpf/socket_proxy type sockops

sudo bpftool cgroup attach "/sys/fs/cgroup" sockops pinned "/sys/fs/bpf/socket_proxy"

sudo bpftool map pin id 370 "/sys/fs/bpf/svc_map"

sudo bpftool map pin id 371 "/sys/fs/bpf/sctp_socket_map"

sudo bpftool prog load ./.output/socket_proxy_msg.bpf.o "/sys/fs/bpf/socket_proxy_msg" map name svc_map pinned "/sys/fs/bpf/svc_map" map name sctp_socket_map pinned "/sys/fs/bpf/sctp_socket_map"

sudo bpftool cgroup detach "/sys/fs/cgroup" sock_ops id 1273


sudo bpftool prog load ./.output/sk_lookup.bpf.o /sys/fs/bpf/sk_lookup type sk_lookup


/sys/kernel/debug/tracing/trace_pipe

sctrace ncat 10.88.0.39 8089 --sctp

curl 169.1.1.1:8080

1. Kprope attached to correct function in Kernel Find where SCTP sockets get created 

2. Access socket 


Local Checkout Rgrep 

Strace Filter on specific 

perf-stat For tracing specfic points


 116 struct iphdr {
 117 #if defined(__LITTLE_ENDIAN_BITFIELD)
 118 __u8 ihl:4,
 119 version:4;
 120 #elif defined (__BIG_ENDIAN_BITFIELD)
 121 __u8 version:4,
 122 ihl:4;
 125 #endif
 126 __u8 tos;
 127 __u16 tot_len;
 128 __u16 id;
 129 __u16 frag_off;
 130 __u8 ttl;
 131 __u8 protocol;
 132 __u16 check;
 133 __u32 saddr;
 134 __u32 daddr;
 136 };

 strace -e trace=getsockopt,setsockopt,socket,bind,listen,recvmsg,sendmsg,close,connect ncat 10.88.0.39 8089 --sctp


SCTP 
socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(8089), sin_addr=inet_addr("10.88.0.39")}, 16) = -1 EINPROGRESS (Operation now in progress)
getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0

UDP 
socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 3
setsockopt(3, SOL_SOCKET, SO_BROADCAST, [1], 4) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(8081), sin_addr=inet_addr("192.168.10.2")}, 16) = 0
getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0           


TCP 
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 5
connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("169.1.1.1")}, 16) = -1 EINPROGRESS (Operation now in progress)


apk add --no-cache nmap-ncat

while true; do { echo -e 'HTTP/1.1 200 OK\r\n\r\nHello World'; } | nc -v -l 80; done



sudo bpftool prog load ./.output/sk_lookup.bpf.o /sys/fs/bpf/sk_lookup type sk_lookup

clang -I/usr/include -I/home/astoycos/go/src/github.com/redhat-et/net-ebpf-playground/libbpf -g -O2 -Wall -Wextra /home/astoycos/go/src/github.com/redhat-et/net-ebpf-playground/userspace/attach-sklookup.c -o attach-sklookup

sudo ./attach-sklookup /sys/fs/bpf/sk_lookup /sys/fs/bpf/sk_lookup_link

sudo bpftool prog -d load ./.output/sock_ops.bpf.o /sys/fs/bpf/load_sock type sockops

 

sudo bpftool cgroup attach "/sys/fs/cgroup" sock_ops pinned "/sys/fs/bpf/load_sock"

sudo bpftool map pin name socket_map "/sys/fs/bpf/socket_map"

sudo bpftool map pin id 371 "/sys/fs/bpf/sctp_socket_map"

sudo bpftool cgroup detach "/sys/fs/cgroup" sock_ops name load_sock

python3 -m http.server

sudo nc -4kle /bin/cat 127.0.0.1 80
python3 -m http.server

{ echo 'Hip'; sleep 0.1; } | nc -4 127.0.0.1 80

clang -I/usr/include -I/home/astoycos/go/src/github.com/redhat-et/net-ebpf-playground/libbpf -g -O2 -Wall -Wextra /home/astoycos/go/src/github.com/redhat-et/net-ebpf-playground/userspace/attach-sklookup.c -o attach-sklookup

sudo bpftool prog load ./.output/sk_lookup.bpf.o /sys/fs/bpf/sk_lookup //map name socket_map pinned "/sys/fs/bpf/socket_map"

sudo ./attach-sklookup /sys/fs/bpf/sk_lookup /sys/fs/bpf/sk_lookup_link

clang -I/usr/include -I/home/astoycos/go/src/github.com/redhat-et/net-ebpf-playground/libbpf -g -O2 -Wall -Wextra /home/astoycos/go/src/github.com/redhat-et/net-ebpf-playground/userspace/socket_bind.c -o socket_bind

sudo bpftool prog load ./.output/sk_msg.bpf.o "/sys/fs/bpf/sk_msg" map name socket_map pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog attach pinned "/sys/fs/bpf/sk_msg" msg_verdict pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog detach name msg_redirect msg_verdict pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog loadall ./.output/sk_skb.bpf.o "/sys/fs/bpf/sk_skb" map name socket_map pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog attach name skb_prog1 stream_parser pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog attach name skb_prog2 stream_verdict pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog detach name skb_prog1 stream_parser pinned "/sys/fs/bpf/socket_map"

sudo bpftool prog detach name skb_prog2 stream_verdict pinned "/sys/fs/bpf/socket_map"


bpftool map delete name socket_map 0xc0 0xa8 0x7a 0x5b 0xc0 0xa8 0x7a 0x01  0x00 0x16 0x00 0x00