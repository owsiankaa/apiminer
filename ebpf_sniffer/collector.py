"""Kolektor: czyta zdarzenia z loadera eBPF, składa TCP -> HTTP i zapisuje pełne wymiany do /data/exchanges.jsonl."""
from __future__ import annotations

import json
import os
import queue
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common.httpwire import FlowTable  # noqa: E402
from common.logs import get_logger  # noqa: E402
from common.traffic import exchange_to_record  # noqa: E402

log = get_logger("collector")
DATA = os.getenv("DATA_DIR", "/data")
PORT = int(os.getenv("TARGET_PORT", "3000"))
OUT = os.path.join(DATA, "exchanges.jsonl")
STATS = os.path.join(DATA, "collector_stats.json")
EXPLORER_DONE = os.path.join(DATA, "explorer_done.flag")
COLLECTOR_DONE = os.path.join(DATA, "collector_done.flag")
GRACE = float(os.getenv("COLLECTOR_GRACE_S", "4"))


def ip_str(raw: int) -> str:
    return socket.inet_ntoa(struct.pack("=I", raw))


def reader(proc: subprocess.Popen, q: "queue.Queue[bytes | None]") -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        q.put(line)
    q.put(None)


def main() -> None:
    os.makedirs(DATA, exist_ok=True)
    for p in (OUT, STATS, COLLECTOR_DONE):
        if os.path.exists(p):
            os.remove(p)

    proc = subprocess.Popen(["./loader"], stdout=subprocess.PIPE, bufsize=1 << 20)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    q: "queue.Queue[bytes | None]" = queue.Queue(maxsize=200_000)
    threading.Thread(target=reader, args=(proc, q), daemon=True).start()

    table = FlowTable(PORT, idle_timeout=float(os.getenv("FLOW_IDLE_S", "30")))
    kernel = {"events": 0, "dropped": 0, "truncated": 0}
    ex_id = 0
    static_n = api_n = 0
    last_event = time.time()
    done_written = False
    tls_warned = False

    def emit(fh, exchanges) -> None:
        nonlocal ex_id, static_n, api_n
        for ex in exchanges:
            if ex.req is None:
                continue
            ex_id += 1
            rec = exchange_to_record(ex_id, ex.conn, ex.req, ex.resp, ex.latency_us)
            if rec["kind"] == "api":
                api_n += 1
            elif rec["kind"] == "static":
                static_n += 1
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if rec["kind"] == "api":
                st = rec["response"]["status"] if rec["response"] else "-"
                log.info("%s %s -> %s", rec["request"]["method"], rec["request"]["path"], st)
        fh.flush()

    def write_stats() -> None:
        with open(STATS, "w", encoding="utf-8") as f:
            json.dump({"kernel": kernel, "flows": table.stats, "exchanges_api": api_n, "exchanges_static": static_n, "ts": time.time()}, f)

    with open(OUT, "a", encoding="utf-8") as fh:
        while not stop.is_set():
            try:
                line = q.get(timeout=0.5)
            except queue.Empty:
                line = b"__TICK__"
            now = time.time()
            if line is None:
                log.error("loader zakończył działanie (kod %s)", proc.poll())
                break
            if line.startswith(b"EVT|"):
                parts = line.rstrip().split(b"|")
                if len(parts) != 12:
                    continue
                _, _dir, sa, da, sp, dp, fl, seq, _ack, ts, ln, hexd = parts
                data = bytes.fromhex(hexd.decode()) if hexd else b""
                last_event = now
                emit(fh, table.feed_event(ip_str(int(sa)), ip_str(int(da)), int(sp), int(dp), int(seq), int(fl), data, now, int(ts)))
            elif line.startswith(b"STAT|"):
                _, e, d, t = line.rstrip().split(b"|")
                kernel.update(events=int(e), dropped=int(d), truncated=int(t))
                if int(d):
                    log.warning("Kernel ring buffer: %s zdarzeń odrzuconych – zwiększ rozmiar rb lub zmniejsz tempo", d.decode())
                write_stats()
            emit(fh, table.gc(now))
            if table.stats["tls_conns"] and not tls_warned:
                tls_warned = True
                log.warning("Wykryto ruch TLS (%d połączeń) – eBPF TC widzi tylko szyfrogram. Użyj HTTP lub terminacji TLS przed targetem.", table.stats["tls_conns"])
            if os.path.exists(EXPLORER_DONE) and not done_written and now - last_event > GRACE:
                emit(fh, table.gc(now, force=True))
                write_stats()
                with open(COLLECTOR_DONE, "w", encoding="utf-8") as f:
                    f.write("done\n")
                done_written = True
                log.info("Explorer zakończył, ruch zdrenowany: %d wymian API, %d statycznych.", api_n, static_n)
        emit(fh, table.gc(time.time(), force=True))
        write_stats()
    proc.terminate()


if __name__ == "__main__":
    main()
