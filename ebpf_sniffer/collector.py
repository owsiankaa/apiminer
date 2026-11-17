import json
import os
import re
import subprocess
import time
from collections import defaultdict

WRAPPER_C = """
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

struct event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  direction;
    __u32 payload_len;
    char  payload[1500];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    printf("EVT|%u|%u|%u|%u|%u|%u|", e->direction, e->saddr, e->daddr, e->sport, e->dport, e->payload_len);
    for (size_t i = 0; i < e->payload_len; i++) {
        printf("%02x", (unsigned char)e->payload[i]);
    }
    printf("\\n");
    fflush(stdout);
    return 0;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open_file("http_sniffer.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open failed\\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\\n"); return 1; }

    int prog_in_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress"));
    int prog_eg_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress"));
    int map_fd = bpf_object__find_map_fd_by_name(obj, "rb");

    int ifindex = if_nametoindex("eth0");
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    bpf_tc_hook_create(&hook);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_in, .prog_fd = prog_in_fd);
    hook.attach_point = BPF_TC_INGRESS;
    bpf_tc_attach(&hook, &opts_in);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_eg, .prog_fd = prog_eg_fd);
    hook.attach_point = BPF_TC_EGRESS;
    bpf_tc_attach(&hook, &opts_eg);

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    fprintf(stderr, "[eBPF] TC hooks aktywne na eth0! Nasłuchuję ruchu TCP na porcie 3000...\\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
"""

HTTP_START_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+HTTP/1\.[01]|^HTTP/1\.[01]\s+(\d{3})")


def normalize_endpoint(path: str) -> str:
    clean_path = path.split("?")[0]
    return re.sub(r"/\d+(?=/|$)", "/{id}", clean_path)


def is_api_traffic(raw_http: str) -> bool:
    lower = raw_http.lower()
    if any(ext in lower for ext in ["text/html", "text/css", "javascript", "image/", "font/"]):
        return False
    first_line = raw_http.splitlines()[0] if raw_http.splitlines() else ""
    if any(first_line.startswith(f"GET {p}") for p in ["/ ", "/assets/", "/main", "/polyfills", "/runtime", "/vendor", "/styles", "/favicon", "/socket.io"]):
        return False
    return "application/json" in lower or "/api/" in first_line or "/rest/" in first_line


def main():
    with open("loader.c", "w") as f:
        f.write(WRAPPER_C)
    subprocess.run(["gcc", "-O2", "loader.c", "-lbpf", "-o", "loader"], check=True)

    out_path = "/data/traffic.jsonl"
    os.makedirs("/data", exist_ok=True)
    if os.path.exists(out_path):
        os.remove(out_path)

    proc = subprocess.Popen(["./loader"], stdout=subprocess.PIPE, text=True)
    stream_buffers = defaultdict(str)

    def flush_buffer(flow_key, log_file):
        buf = stream_buffers.get(flow_key, "")
        if not buf:
            return
        stream_buffers[flow_key] = ""

        if not HTTP_START_RE.match(buf):
            return
        if not is_api_traffic(buf):
            return

        direction, _, _, sport, dport = flow_key
        first_line = buf.splitlines()[0]
        parts = first_line.split()
        method = parts[0] if direction == "request" and len(parts) >= 2 else None
        raw_path = parts[1] if direction == "request" and len(parts) >= 2 else None
        endpoint_tpl = normalize_endpoint(raw_path) if raw_path else None

        record = {
            "timestamp": time.time(),
            "direction": direction,
            "sport": int(sport),
            "dport": int(dport),
            "method": method,
            "path": raw_path,
            "endpoint_template": endpoint_tpl,
            "raw_http": buf[:4096],
        }
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")
        log_file.flush()
        print(f"[eBPF Stream] {direction.upper()}: {first_line}")

    with open(out_path, "a", encoding="utf-8") as log_file:
        for line in proc.stdout:
            if not line.startswith("EVT|"):
                continue
            parts = line.strip().split("|")
            if len(parts) != 8:
                continue
            _, dir_code, saddr, daddr, sport, dport, _, hex_data = parts
            direction = "request" if dir_code == "0" else "response"
            flow_key = (direction, saddr, daddr, sport, dport)

            chunk = bytes.fromhex(hex_data).decode("utf-8", errors="replace")

            if HTTP_START_RE.match(chunk) and stream_buffers[flow_key]:
                flush_buffer(flow_key, log_file)

            stream_buffers[flow_key] += chunk

            if "\r\n\r\n" in stream_buffers[flow_key]:
                headers, body = stream_buffers[flow_key].split("\r\n\r\n", 1)
                cl_match = re.search(r"content-length:\s*(\d+)", headers, re.I)
                if cl_match:
                    expected_len = int(cl_match.group(1))
                    if len(body.encode("utf-8")) >= expected_len:
                        flush_buffer(flow_key, log_file)
                else:
                    flush_buffer(flow_key, log_file)


if __name__ == "__main__":
    main()
