#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "event.h"

static volatile sig_atomic_t exiting = 0;
static void on_sig(int s) { (void)s; exiting = 1; }

static int handle_event(void *ctx, void *data, size_t sz) {
    static const char HEX[] = "0123456789abcdef";
    static char line[256 + 2 * CHUNK];
    const struct event *e = data;
    (void)ctx; (void)sz;
    int n = snprintf(line, 200, "EVT|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%u|", e->direction, e->saddr, e->daddr, e->sport,
                     e->dport, e->flags, e->seq, e->ack, (unsigned long long)e->ts_ns, e->payload_len);
    unsigned len = e->payload_len > CHUNK ? CHUNK : e->payload_len;
    for (unsigned i = 0; i < len; i++) {
        line[n++] = HEX[e->payload[i] >> 4];
        line[n++] = HEX[e->payload[i] & 15];
    }
    line[n++] = '\n';
    fwrite(line, 1, n, stdout);
    return 0;
}

static void print_stats(int fd, int ncpu) {
    __u64 *vals = calloc(ncpu, sizeof(__u64));
    unsigned long long tot[STAT_MAX] = {0};
    if (!vals) return;
    for (__u32 k = 0; k < STAT_MAX; k++) {
        if (bpf_map_lookup_elem(fd, &k, vals) == 0)
            for (int c = 0; c < ncpu; c++) tot[k] += vals[c];
    }
    free(vals);
    printf("STAT|%llu|%llu|%llu\n", tot[STAT_EVENTS], tot[STAT_DROPPED], tot[STAT_TRUNC]);
}

int main(void) {
    const char *iface = getenv("IFACE") ? getenv("IFACE") : "eth0";
    int port = getenv("TARGET_PORT") ? atoi(getenv("TARGET_PORT")) : 3000;
    const char *ready = getenv("READY_FLAG") ? getenv("READY_FLAG") : "/data/sniffer_ready.flag";
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);

    struct bpf_object *obj = bpf_object__open_file("http_sniffer.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open failed: %s\n", strerror(errno)); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed (verifier?): %s\n", strerror(errno)); return 1; }

    struct bpf_program *pin = bpf_object__find_program_by_name(obj, "tc_ingress");
    struct bpf_program *peg = bpf_object__find_program_by_name(obj, "tc_egress");
    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "cfg");
    int st_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    int rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (!pin || !peg || cfg_fd < 0 || st_fd < 0 || rb_fd < 0) { fprintf(stderr, "program/map missing\n"); return 1; }

    __u32 k0 = 0; __u64 pv = (__u64)port;
    if (bpf_map_update_elem(cfg_fd, &k0, &pv, BPF_ANY)) { fprintf(stderr, "cfg update failed\n"); return 1; }

    int ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "interface %s not found\n", iface); return 1; }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) { fprintf(stderr, "tc hook create failed: %d\n", err); return 1; }

    for (int dir = 0; dir < 2; dir++) {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, h, .ifindex = ifindex, .attach_point = dir ? BPF_TC_EGRESS : BPF_TC_INGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, o, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(dir ? peg : pin));
        err = bpf_tc_attach(&h, &o);
        if (err == -EEXIST) { /* pozostałość po poprzednim uruchomieniu */
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, d, .handle = 1, .priority = 1);
            bpf_tc_detach(&h, &d);
            o.prog_fd = bpf_program__fd(dir ? peg : pin);
            o.prog_id = 0; o.flags = 0;
            err = bpf_tc_attach(&h, &o);
        }
        if (err) { fprintf(stderr, "tc attach (%s) failed: %d\n", dir ? "egress" : "ingress", err); return 1; }
    }

    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer failed\n"); return 1; }

    FILE *f = fopen(ready, "w");
    if (f) { fputs("ready\n", f); fclose(f); }
    fprintf(stderr, "[eBPF] TC hooks aktywne na %s, port TCP %d\n", iface, port);

    int ncpu = libbpf_num_possible_cpus();
    time_t last = time(NULL);
    while (!exiting) {
        int n = ring_buffer__poll(rb, 100);
        if (n < 0 && n != -EINTR) break;
        if (time(NULL) - last >= 5) { print_stats(st_fd, ncpu); last = time(NULL); }
    }
    print_stats(st_fd, ncpu);
    ring_buffer__free(rb);

    for (int dir = 0; dir < 2; dir++) {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, h, .ifindex = ifindex, .attach_point = dir ? BPF_TC_EGRESS : BPF_TC_INGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, d, .handle = 1, .priority = 1);
        bpf_tc_detach(&h, &d);
    }
    bpf_tc_hook_destroy(&hook);
    bpf_object__close(obj);
    return 0;
}
