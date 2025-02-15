#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>  // برای استفاده از ntohl
#include <netinet/in.h>

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(max_entries, 16);
} flow_stats SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ntohl(iph->saddr);  // اصلاح شده
    key.dst_ip = ntohl(iph->daddr);  // اصلاح شده
    key.protocol = iph->protocol;

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        __u64 hdr_size = sizeof(struct ethhdr) + (iph->ihl * 4);
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = data + hdr_size;
            if ((void*)(tcph + 1) > data_end)
                return XDP_PASS;
            key.src_port = tcph->source;
            key.dst_port = tcph->dest;
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = data + hdr_size;
            if ((void*)(udph + 1) > data_end)
                return XDP_PASS;
            key.src_port = udph->source;
            key.dst_port = udph->dest;
        }
    } else {
        key.src_port = 0;
        key.dst_port = 0;
    }

    __u64 bytes = (__u64)(data_end - data);
    __u64 *value = bpf_map_lookup_elem(&flow_stats, &key);
    if (value)
        __sync_fetch_and_add(value, bytes);
    else
        bpf_map_update_elem(&flow_stats, &key, &bytes, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
