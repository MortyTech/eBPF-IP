#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// Define a map to store byte counts for the target IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // IP address as key
    __type(value, __u64); // Byte count as value
} ip_byte_count SEC(".maps");

// Target IP address (185.79.97.55 in network byte order)
#define TARGET_IP 0x37614FB9 // 185.79.97.55 in little-endian

SEC("xdp")
int xdp_count_bytes(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    // Check if the packet is IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    // Check if the packet is for the target IP
    if (ip->daddr == TARGET_IP) {
        __u32 key = TARGET_IP;
        __u64 *value;

        // Look up the byte count in the map
        value = bpf_map_lookup_elem(&ip_byte_count, &key);
        if (value) {
            (*value) += (__u64)(ctx->data_end - ctx->data);
        } else {
            __u64 init_val = (__u64)(ctx->data_end - ctx->data);
            bpf_map_update_elem(&ip_byte_count, &key, &init_val, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
