FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    iproute2 \
    python3 \
    python3-pip \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Linkujemy bpftool niezależnie od dokładnej wersji podkatalogu w /usr/lib/linux-tools
RUN ln -sf $(find /usr/lib/linux-tools* -name bpftool | head -n 1) /usr/local/bin/bpftool || true

WORKDIR /app
COPY http_sniffer.bpf.c collector.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]
