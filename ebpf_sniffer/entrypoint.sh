#!/bin/bash
set -euo pipefail

echo "[eBPF] Generowanie vmlinux.h z BTF jądra..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

case "$(uname -m)" in
  aarch64) BPF_ARCH=arm64 ;;
  *)       BPF_ARCH=x86 ;;
esac

echo "[eBPF] Kompilacja http_sniffer.bpf.c (arch=$BPF_ARCH)..."
clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} -I. -c http_sniffer.bpf.c -o http_sniffer.bpf.o

echo "[eBPF] Kompilacja loadera..."
gcc -O2 -Wall loader.c -lbpf -o loader

echo "[eBPF] Start kolektora Python..."
exec python3 -u collector.py
