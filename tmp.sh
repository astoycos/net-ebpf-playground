sudo bpftool prog -d load ./.output/socket_proxy.bpf.o /sys/fs/bpf/socket_proxy type sockops

sudo bpftool cgroup attach "/sys/fs/cgroup" sock_ops pinned "/sys/fs/bpf/socket_proxy"

sudo bpftool map pin id 370 "/sys/fs/bpf/svc_map"

sudo bpftool map pin id 371 "/sys/fs/bpf/sctp_socket_map"

sudo bpftool prog load ./.output/socket_proxy_msg.bpf.o "/sys/fs/bpf/socket_proxy_msg" map name svc_map pinned "/sys/fs/bpf/svc_map" map name sctp_socket_map pinned "/sys/fs/bpf/sctp_socket_map"

sudo bpftool cgroup detach "/sys/fs/cgroup" sock_ops id 1273

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