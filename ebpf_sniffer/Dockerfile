FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-tools-common linux-tools-generic iproute2 \
    python3 python3-rich python3-brotli gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# bpftool niezależnie od wersji podkatalogu w /usr/lib/linux-tools
RUN ln -sf "$(find /usr/lib/linux-tools* -name bpftool | head -n 1)" /usr/local/bin/bpftool || true

WORKDIR /app
COPY ebpf_sniffer/http_sniffer.bpf.c ebpf_sniffer/loader.c ebpf_sniffer/event.h ebpf_sniffer/collector.py ebpf_sniffer/entrypoint.sh ./
COPY common ./common
RUN chmod +x entrypoint.sh
CMD ["./entrypoint.sh"]
