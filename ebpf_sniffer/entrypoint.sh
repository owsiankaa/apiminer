#!/bin/bash
set -e

echo "[eBPF] Generowanie vmlinux.h z BTF jądra..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    BPF_ARCH="arm64"
else
    BPF_ARCH="x86"
fi

echo "[eBPF] Kompilacja http_sniffer.bpf.c dla architektury $BPF_ARCH..."
clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} -I. -c http_sniffer.bpf.c -o http_sniffer.bpf.o

echo "[eBPF] Uruchamianie kolektora Python..."
python3 -u collector.py
