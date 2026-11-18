#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "event.h"

#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IPPROTO_TCP 6

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MiB */
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cfg SEC(".maps"); /* cfg[0] = port docelowy (ustawiany przez loader) */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        (*v)++;
}

/* Weryfikator wymaga, by długość dla bpf_skb_load_bytes była PRZEDSTAWIONA jako 1..CHUNK w rejestrze przekazywanym do helpera.
 * Warunki if (len < 1) clang stosuje do kopii rejestru (stąd "size=0"), więc zakres wymuszamy arytmetyką:
 * ((len-1) & 0x7ff) + 1  ==> zawsze 1..2048, każda kopia rejestru dziedziczy te granice.
 * Bariera asm przed działaniem uniemożliwia clangowi uproszczenie wyrażenia do `len`.
 * Kontrakt: wołający gwarantuje 1 <= len <= CHUNK. */
static __always_inline long load_chunk(struct __sk_buff *skb, __u32 off, void *dst, __u32 len) {
    asm volatile("" : "+r"(len));
    len = ((len - 1) & (CHUNK - 1)) + 1; /* CHUNK=2048 => maska 0x7ff */
    return bpf_skb_load_bytes(skb, off, dst, len);
}

static __always_inline int process(struct __sk_buff *skb, __u8 dir) {
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 0;

    __u32 k = 0;
    __u64 *portp = bpf_map_lookup_elem(&cfg, &k);
    if (!portp)
        return 0;
    __u16 target = (__u16)*portp;

    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0)
        return 0;
    if (iph.protocol != IPPROTO_TCP)
        return 0;
    __u32 ihl = iph.ihl * 4;
    if (ihl < sizeof(iph) || ihl > 60)
        return 0;

    struct tcphdr th;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + ihl, &th, sizeof(th)) < 0)
        return 0;
    __u16 sport = bpf_ntohs(th.source), dport = bpf_ntohs(th.dest);
    if (sport != target && dport != target)
        return 0;
    __u32 thl = th.doff * 4;
    if (thl < sizeof(th) || thl > 60)
        return 0;

    __u8 flags = (th.fin ? F_FIN : 0) | (th.syn ? F_SYN : 0) | (th.rst ? F_RST : 0) | (th.psh ? F_PSH : 0) | (th.ack ? F_ACK : 0);
    __u32 off = ETH_HLEN + ihl + thl;
    __u32 plen = skb->len > off ? skb->len - off : 0;
    if (plen == 0 && !(flags & (F_FIN | F_RST | F_SYN)))
        return 0; /* czyste ACK nas nie interesują; SYN daje ISN, FIN/RST domykają strumień */

    __u32 seq = bpf_ntohl(th.seq);
    __u32 nchunks = plen ? (plen + CHUNK - 1) / CHUNK : 1;
    if (nchunks > MAX_CHUNKS) {
        bump(STAT_TRUNC);
        nchunks = MAX_CHUNKS;
    }

    for (int c = 0; c < MAX_CHUNKS; c++) {
        if ((__u32)c >= nchunks)
            break;
        __u32 coff = (__u32)c * CHUNK;
        __u32 clen = plen > coff ? plen - coff : 0;
        if (clen > CHUNK)
            clen = CHUNK;

        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) {
            bump(STAT_DROPPED);
            return 0;
        }
        e->saddr = iph.saddr;
        e->daddr = iph.daddr;
        e->sport = sport;
        e->dport = dport;
        e->direction = dir;
        e->flags = flags;
        e->seq = seq + coff;
        e->ack = bpf_ntohl(th.ack_seq);
        e->ts_ns = bpf_ktime_get_ns();
        e->payload_len = (__u16)clen;
        if (clen > 0) {
            if (load_chunk(skb, off + coff, e->payload, clen) < 0) {
                bpf_ringbuf_discard(e, 0);
                return 0;
            }
        }
        bpf_ringbuf_submit(e, 0);
        bump(STAT_EVENTS);
    }
    return 0;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    process(skb, 0);
    return 0; /* TC_ACT_OK – nigdy nie zakłócamy ruchu */
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    process(skb, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
