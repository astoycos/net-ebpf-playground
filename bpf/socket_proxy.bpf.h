#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Stored in Network Endian

struct svc_backend { 
    __u32 address;     
    __u32 dport;      
};

struct svc_vip {
    __u32 address;     
    __u32 dport;      
};

struct { 
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct svc_vip);
    __type(value, struct svc_backend); 
    __uint(max_entries, 65536);
} svc_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH); 
  __type(key, struct svc_vip);
  __type(value, __u32); 
  __uint(max_entries, 65536);
  __uint(map_flags, 0);
} sctp_socket_map SEC(".maps");