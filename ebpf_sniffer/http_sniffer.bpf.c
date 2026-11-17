#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TARGET_PORT 3000
#define MAX_PAYLOAD 1500

struct event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  direction;
    __u32 payload_len;
    char  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb SEC(".maps");

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction) {
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return 0;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->protocol != IPPROTO_TCP)
        return 0;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return 0;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return 0;

    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);

    if (sport != TARGET_PORT && dport != TARGET_PORT)
        return 0;

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr))
        return 0;

    __u32 payload_offset = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;
    __u8 *payload_ptr = (__u8 *)data + payload_offset;

    if ((void *)(payload_ptr + 1) > data_end)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->saddr = ip->saddr;
    e->daddr = ip->daddr;
    e->sport = sport;
    e->dport = dport;
    e->direction = direction;

    __u32 copied = 0;
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD; i++) {
        if ((void *)(payload_ptr + i + 1) > data_end)
            break;
        e->payload[i] = payload_ptr[i];
        copied++;
    }

    if (copied == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->payload_len = copied;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    process_packet(skb, 0);
    return 0;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    process_packet(skb, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
