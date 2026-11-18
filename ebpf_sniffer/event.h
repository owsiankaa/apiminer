#ifndef APIMINER_EVENT_H
#define APIMINER_EVENT_H
/* Wspólny układ zdarzenia dla programu BPF i loadera (bez własnych #include – typy dostarcza includer). */
#define CHUNK 2048
#define MAX_CHUNKS 24 /* 48 KiB na skb (GSO/TSO) */

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10

struct event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 direction; /* 0 = ingress, 1 = egress (informacyjnie) */
    __u8 flags;
    __u16 payload_len;
    __u32 seq; /* numer sekwencyjny pierwszego bajtu TEGO fragmentu */
    __u32 ack;
    __u64 ts_ns; /* bpf_ktime_get_ns (monotoniczny) */
    __u8 payload[CHUNK];
};

enum { STAT_EVENTS = 0, STAT_DROPPED = 1, STAT_TRUNC = 2, STAT_MAX = 3 };
#endif
