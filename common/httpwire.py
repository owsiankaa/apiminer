"""Reasemblacja strumieni TCP + przyrostowy parser HTTP/1.x (bez zależności zewnętrznych).

Obsługuje: segmenty poza kolejnością, retransmisje/nakładanie, luki (timeout + resync), Content-Length,
Transfer-Encoding: chunked, body do zamknięcia połączenia, 1xx/204/304/HEAD, pipelining, gzip/deflate/(br),
wykrywanie TLS / HTTP/2 (bez dekodowania).
"""
from __future__ import annotations

import os
import re
import zlib
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Tuple

MAX_HEAD_BYTES = 64 * 1024
MAX_BODY_KEEP = int(os.getenv("MAX_BODY_BYTES", str(1 << 20)))
MAX_DECODED = int(os.getenv("MAX_DECODED_BYTES", str(8 << 20)))
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

REQ_START = re.compile(rb"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE) \S{1,4096} HTTP/1\.[01]\r\n")
RESP_START = re.compile(rb"HTTP/1\.[01] \d{3}[ \r]")
REQ_LINE = re.compile(r"^([A-Z]+) (\S+) HTTP/(1\.[01])$")
RESP_LINE = re.compile(r"^HTTP/(1\.[01]) (\d{3})(?: (.*))?$")


def seq_diff(a: int, b: int) -> int:
    """Różnica numerów sekwencyjnych TCP z uwzględnieniem zawinięcia 32-bit (a - b)."""
    return ((a - b + 0x80000000) & 0xFFFFFFFF) - 0x80000000


# --------------------------------------------------------------------------------------------------
# TCP
# --------------------------------------------------------------------------------------------------
class TcpStream:
    """Składa jednokierunkowy strumień bajtów z segmentów (po seq)."""

    def __init__(self, max_pending_bytes: int = 4 << 20, hole_timeout: float = 3.0):
        self.next_seq: Optional[int] = None
        self.pending: Dict[int, bytes] = {}
        self.pending_bytes = 0
        self.hole_since: Optional[float] = None
        self.max_pending = max_pending_bytes
        self.hole_timeout = hole_timeout
        self.gaps = 0
        self.retransmits = 0
        self._gap_flag = False

    def take_gap(self) -> bool:
        g, self._gap_flag = self._gap_flag, False
        return g

    def add(self, seq: int, data: bytes, now: float) -> bytes:
        if not data:
            return b""
        if self.next_seq is None:
            self.next_seq = seq
        out = bytearray()
        d = seq_diff(seq, self.next_seq)
        if d < 0:  # retransmisja / nakładanie
            if -d >= len(data):
                self.retransmits += 1
                return b""
            data = data[-d:]
            d = 0
        if d == 0:
            out += data
            self.next_seq = (self.next_seq + len(data)) & 0xFFFFFFFF
            out += self._drain()
        else:
            old = self.pending.get(seq)
            if old is None or len(old) < len(data):
                self.pending_bytes += len(data) - (len(old) if old else 0)
                self.pending[seq] = data
            if self.hole_since is None:
                self.hole_since = now
        out += self.poll(now)
        return bytes(out)

    def _drain(self) -> bytes:
        out = bytearray()
        progressed = True
        while self.pending and progressed:
            progressed = False
            for s in sorted(self.pending, key=lambda x: seq_diff(x, self.next_seq)):
                d = seq_diff(s, self.next_seq)
                if d > 0:
                    break
                data = self.pending.pop(s)
                self.pending_bytes -= len(data)
                progressed = True
                if -d >= len(data):
                    break
                if d < 0:
                    data = data[-d:]
                out += data
                self.next_seq = (self.next_seq + len(data)) & 0xFFFFFFFF
                break
        if not self.pending:
            self.hole_since = None
        return bytes(out)

    def skip_gap(self) -> bytes:
        if not self.pending:
            return b""
        s = min(self.pending, key=lambda x: seq_diff(x, self.next_seq))
        self.next_seq = s
        self.gaps += 1
        self._gap_flag = True
        self.hole_since = None
        return self._drain()

    def poll(self, now: float) -> bytes:
        if self.pending and (
            self.pending_bytes > self.max_pending or (self.hole_since is not None and now - self.hole_since > self.hole_timeout)
        ):
            return self.skip_gap()
        return b""


# --------------------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------------------
@dataclass
class HttpMessage:
    is_request: bool
    headers: Dict[str, str] = field(default_factory=dict)
    method: str = ""
    target: str = ""
    version: str = "1.1"
    status: int = 0
    reason: str = ""
    body: bytes = b""
    wire_len: int = 0
    truncated: bool = False
    incomplete: bool = False
    gap: bool = False
    encoding_note: str = ""
    interim: bool = False
    ts: float = 0.0
    ts_end: float = 0.0
    mono_ns: int = 0


def decode_body(body: bytes, encoding: str) -> Tuple[bytes, str]:
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity" or not body:
        return body, ""
    data = body
    for e in reversed([x.strip() for x in enc.split(",") if x.strip()]):
        try:
            if e in ("gzip", "x-gzip"):
                data = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_DECODED)
            elif e == "deflate":
                try:
                    data = zlib.decompressobj().decompress(data, MAX_DECODED)
                except zlib.error:
                    data = zlib.decompressobj(-zlib.MAX_WBITS).decompress(data, MAX_DECODED)
            elif e == "br":
                import brotli  # type: ignore

                data = brotli.decompress(data)
            else:
                return data, f"unsupported-encoding:{e}"
        except ImportError:
            return data, "brotli-not-installed"
        except Exception as ex:  # noqa: BLE001
            return data, f"decode-error:{e}:{type(ex).__name__}"
    return data, ""


class HttpParser:
    """Przyrostowy parser jednego kierunku połączenia (żądania LUB odpowiedzi)."""

    def __init__(self, is_request: bool, nobody_hint: Optional[Callable[[], bool]] = None):
        self.is_request = is_request
        self.nobody_hint = nobody_hint
        self.buf = bytearray()
        self.state = "head"
        self.resync = True  # start w środku strumienia jest dozwolony
        self.dead = False  # Upgrade (WebSocket) / TLS / h2
        self._reset_msg()

    def _reset_msg(self) -> None:
        self.msg: Optional[HttpMessage] = None
        self.body = bytearray()
        self.body_len = 0
        self.body_truncated = False
        self.remaining = 0
        self.chunk_remaining = 0

    # ---- API
    def feed(self, data: bytes, now: float, gap: bool = False, mono_ns: int = 0) -> List[HttpMessage]:
        out: List[HttpMessage] = []
        if self.dead:
            return out
        if gap:
            if self.msg is not None:
                out.append(self._finish(now, incomplete=True, gap=True))
            self.buf.clear()
            self.state = "head"
            self.resync = True
        self.buf.extend(data)
        while True:
            st = self.state
            if st == "head":
                if self.resync:
                    rx = REQ_START if self.is_request else RESP_START
                    m = rx.search(self.buf)
                    if not m:
                        if len(self.buf) > 32:
                            del self.buf[:-32]
                        break
                    del self.buf[: m.start()]
                    self.resync = False
                end = self.buf.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.buf) > MAX_HEAD_BYTES:
                        self.buf.clear()
                        self.resync = True
                    break
                head = bytes(self.buf[:end])
                del self.buf[: end + 4]
                msg = self._parse_head(head)
                if msg is None:
                    self.resync = True
                    continue
                msg.ts, msg.mono_ns = now, mono_ns
                self.msg = msg
                self._begin_body()
            elif st == "done":
                m = self._finish(now)
                if m.interim:
                    self.state = "head"
                    continue
                out.append(m)
                if m.status == 101 and not self.is_request:
                    self.dead = True
                    break
                self.state = "head"
            elif st == "body_cl":
                take = min(len(self.buf), self.remaining)
                self._append(self.buf[:take])
                del self.buf[:take]
                self.remaining -= take
                if self.remaining == 0:
                    self.state = "done"
                else:
                    break
            elif st == "chunk_size":
                i = self.buf.find(b"\r\n")
                if i < 0:
                    if len(self.buf) > 1024:
                        self._protocol_error()
                    break
                line = bytes(self.buf[:i]).split(b";")[0].strip()
                try:
                    size = int(line, 16)
                except ValueError:
                    self._protocol_error()
                    continue
                del self.buf[: i + 2]
                if size == 0:
                    self.state = "trailers"
                else:
                    self.chunk_remaining = size
                    self.state = "chunk_data"
            elif st == "chunk_data":
                take = min(len(self.buf), self.chunk_remaining)
                self._append(self.buf[:take])
                del self.buf[:take]
                self.chunk_remaining -= take
                if self.chunk_remaining == 0:
                    self.state = "chunk_crlf"
                else:
                    break
            elif st == "chunk_crlf":
                if len(self.buf) < 2:
                    break
                del self.buf[:2]
                self.state = "chunk_size"
            elif st == "trailers":
                i = self.buf.find(b"\r\n")
                if i < 0:
                    break
                line = bytes(self.buf[:i])
                del self.buf[: i + 2]
                if not line:
                    self.state = "done"
            elif st == "body_close":
                self._append(self.buf)
                self.buf.clear()
                break
            else:  # pragma: no cover
                break
        return out

    def close(self, now: float) -> List[HttpMessage]:
        """Koniec strumienia (FIN/RST/timeout): domknij wiadomość bez Content-Length lub oznacz jako niekompletną."""
        out: List[HttpMessage] = []
        if self.msg is not None and not self.dead:
            out.append(self._finish(now, incomplete=(self.state != "body_close")))
            self.state = "head"
        return out

    # ---- wewnętrzne
    def _protocol_error(self) -> None:
        self.buf.clear()
        self.state = "head"
        self.resync = True
        self._reset_msg()

    def _parse_head(self, head: bytes) -> Optional[HttpMessage]:
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1")
        headers: Dict[str, str] = {}
        for ln in lines[1:]:
            if b":" not in ln:
                continue
            k, v = ln.split(b":", 1)
            key, val = k.decode("latin-1").strip().lower(), v.decode("latin-1").strip()
            headers[key] = (headers[key] + ("\n" if key == "set-cookie" else ", ") + val) if key in headers else val
        if self.is_request:
            m = REQ_LINE.match(first)
            if not m:
                return None
            return HttpMessage(True, headers=headers, method=m.group(1), target=m.group(2), version=m.group(3))
        m2 = RESP_LINE.match(first)
        if not m2:
            return None
        return HttpMessage(False, headers=headers, version=m2.group(1), status=int(m2.group(2)), reason=m2.group(3) or "")

    def _begin_body(self) -> None:
        m = self.msg
        assert m is not None
        te = m.headers.get("transfer-encoding", "").lower()
        cl_raw = m.headers.get("content-length", "")
        try:
            cl = int(cl_raw.split(",")[0]) if cl_raw else None
        except ValueError:
            cl = None
        if not self.is_request:
            if 100 <= m.status < 200 and m.status != 101:
                m.interim = True
                self.state = "done"
                return
            if m.status in (101, 204, 304) or (self.nobody_hint and self.nobody_hint()):
                self.state = "done"
                return
        if "chunked" in te:
            self.state = "chunk_size"
        elif cl is not None:
            self.remaining = cl
            self.state = "body_cl" if cl > 0 else "done"
        elif self.is_request:
            self.state = "done"
        else:
            self.state = "body_close"

    def _append(self, chunk) -> None:
        self.body_len += len(chunk)
        room = MAX_BODY_KEEP - len(self.body)
        if room > 0:
            self.body += chunk[:room]
        if len(chunk) > max(room, 0):
            self.body_truncated = True

    def _finish(self, now: float, incomplete: bool = False, gap: bool = False) -> HttpMessage:
        m = self.msg
        assert m is not None
        decoded, note = decode_body(bytes(self.body), m.headers.get("content-encoding", ""))
        m.body, m.encoding_note = decoded, note
        m.wire_len, m.truncated, m.incomplete, m.gap, m.ts_end = self.body_len, self.body_truncated, incomplete, gap, now
        self._reset_msg()
        return m


# --------------------------------------------------------------------------------------------------
# Połączenia i tablica przepływów
# --------------------------------------------------------------------------------------------------
@dataclass
class Exchange:
    conn: str
    req: Optional[HttpMessage]
    resp: Optional[HttpMessage]
    latency_us: Optional[int] = None


class Connection:
    def __init__(self, key: Tuple[str, int, str, int], now: float):
        self.key = key
        self.label = f"{key[0]}:{key[1]}->{key[2]}:{key[3]}"
        self.c2s, self.s2c = TcpStream(), TcpStream()
        self.req_parser = HttpParser(True)
        self.resp_parser = HttpParser(False, nobody_hint=self._resp_nobody)
        self.pending: Deque[HttpMessage] = deque()
        self.orphans: Deque[HttpMessage] = deque()
        self.last_seen = now
        self.proto: Optional[str] = None  # http | tls | h2 | None
        self.closed = {"c2s": False, "s2c": False}

    def _resp_nobody(self) -> bool:
        return bool(self.pending) and self.pending[0].method == "HEAD"

    def _pair(self, req: Optional[HttpMessage], resp: Optional[HttpMessage]) -> Exchange:
        lat = None
        if req and resp and req.mono_ns and resp.mono_ns and resp.mono_ns >= req.mono_ns:
            lat = (resp.mono_ns - req.mono_ns) // 1000
        return Exchange(self.label, req, resp, lat)

    def _sniff_proto(self, data: bytes) -> None:
        if self.proto is not None or not data:
            return
        if data[:2] == b"\x16\x03":
            self.proto = "tls"
            self.req_parser.dead = self.resp_parser.dead = True
        elif data.startswith(b"PRI * HTTP/2"):
            self.proto = "h2"
            self.req_parser.dead = self.resp_parser.dead = True
        else:
            self.proto = "http"

    def feed(self, direction: str, seq: int, flags: int, data: bytes, now: float, mono_ns: int = 0) -> List[Exchange]:
        self.last_seen = now
        out: List[Exchange] = []
        stream = self.c2s if direction == "c2s" else self.s2c
        if flags & SYN and stream.next_seq is None:  # ISN znany -> poprawna kolejność nawet gdy 1. segment danych przyjdzie późno
            stream.next_seq = (seq + 1) & 0xFFFFFFFF
        chunk = stream.add(seq, data, now)
        if direction == "c2s":
            self._sniff_proto(chunk or data)
        if chunk:
            out += self._parse(direction, chunk, now, mono_ns, stream.take_gap())
        if flags & (FIN | RST):
            out += self.close_direction(direction, now)
        return out

    def _parse(self, direction: str, chunk: bytes, now: float, mono_ns: int, gap: bool) -> List[Exchange]:
        out: List[Exchange] = []
        if direction == "c2s":
            for req in self.req_parser.feed(chunk, now, gap, mono_ns):
                if self.orphans:
                    out.append(self._pair(req, self.orphans.popleft()))
                else:
                    self.pending.append(req)
        else:
            for resp in self.resp_parser.feed(chunk, now, gap, mono_ns):
                if self.pending:
                    out.append(self._pair(self.pending.popleft(), resp))
                else:
                    self.orphans.append(resp)
        return out

    def close_direction(self, direction: str, now: float) -> List[Exchange]:
        out: List[Exchange] = []
        if self.closed[direction]:
            return out
        self.closed[direction] = True
        stream = self.c2s if direction == "c2s" else self.s2c
        tail = stream.skip_gap() if stream.pending else b""
        if tail:
            out += self._parse(direction, tail, now, 0, stream.take_gap())
        parser = self.req_parser if direction == "c2s" else self.resp_parser
        for m in parser.close(now):
            if direction == "c2s":
                self.pending.append(m)
            elif self.pending:
                out.append(self._pair(self.pending.popleft(), m))
        return out

    def close_all(self, now: float) -> List[Exchange]:
        out = self.close_direction("c2s", now) + self.close_direction("s2c", now)
        while self.pending:  # żądania bez odpowiedzi
            out.append(self._pair(self.pending.popleft(), None))
        return out

    def poll(self, now: float) -> List[Exchange]:
        out: List[Exchange] = []
        for d, s in (("c2s", self.c2s), ("s2c", self.s2c)):
            tail = s.poll(now)
            if tail:
                out += self._parse(d, tail, now, 0, s.take_gap())
        return out


class FlowTable:
    def __init__(self, target_port: int, idle_timeout: float = 30.0, max_conns: int = 5000):
        self.port = target_port
        self.idle = idle_timeout
        self.max_conns = max_conns
        self.conns: Dict[Tuple[str, int, str, int], Connection] = {}
        self.stats = {"segments": 0, "tls_conns": 0, "h2_conns": 0, "gaps": 0, "retransmits": 0, "exchanges": 0}

    def feed_event(self, saddr: str, daddr: str, sport: int, dport: int, seq: int, flags: int, data: bytes,
                   now: float, mono_ns: int = 0) -> List[Exchange]:
        if dport == self.port:
            key, direction = (saddr, sport, daddr, dport), "c2s"
        elif sport == self.port:
            key, direction = (daddr, dport, saddr, sport), "s2c"
        else:
            return []
        self.stats["segments"] += 1
        conn = self.conns.get(key)
        if conn is None:
            if len(self.conns) >= self.max_conns:
                self._evict_oldest(now)
            conn = self.conns[key] = Connection(key, now)
        had = conn.proto
        out = conn.feed(direction, seq, flags, data, now, mono_ns)
        if had is None and conn.proto == "tls":
            self.stats["tls_conns"] += 1
        if had is None and conn.proto == "h2":
            self.stats["h2_conns"] += 1
        if all(conn.closed.values()):
            out += conn.close_all(now)
            self._account(conn)
            self.conns.pop(key, None)
        self.stats["exchanges"] += len(out)
        return out

    def _account(self, conn: Connection) -> None:
        self.stats["gaps"] += conn.c2s.gaps + conn.s2c.gaps
        self.stats["retransmits"] += conn.c2s.retransmits + conn.s2c.retransmits

    def _evict_oldest(self, now: float) -> List[Exchange]:
        key = min(self.conns, key=lambda k: self.conns[k].last_seen)
        conn = self.conns.pop(key)
        self._account(conn)
        return conn.close_all(now)

    def gc(self, now: float, force: bool = False) -> List[Exchange]:
        out: List[Exchange] = []
        for key in list(self.conns):
            conn = self.conns[key]
            out += conn.poll(now)
            if force or now - conn.last_seen > self.idle:
                out += conn.close_all(now)
                self._account(conn)
                self.conns.pop(key, None)
        self.stats["exchanges"] += len(out)
        return out
