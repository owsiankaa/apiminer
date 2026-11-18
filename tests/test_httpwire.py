"""Testy offline parsera/reasemblacji: pytest tests/ (nie wymagają Dockera)."""
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.httpwire import FlowTable, HttpParser  # noqa: E402
from common.traffic import normalize_path  # noqa: E402

REQ = b"POST /api/items/ HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"name\":\"a1\"}"


def feed_all(table, req_chunks, resp_bytes, port=3000):
    """req_chunks: [(seq, bytes)] w dowolnej kolejności; odpowiedź jako jeden segment."""
    out = table.feed_event("1.1.1.1", "2.2.2.2", 5555, port, 999, 0x02, b"", 0.9)  # SYN (ISN=999)
    for seq, d in req_chunks:
        out += table.feed_event("1.1.1.1", "2.2.2.2", 5555, port, seq, 0x18, d, 1.0)
    out += table.feed_event("2.2.2.2", "1.1.1.1", port, 5555, 9000, 0x18, resp_bytes, 1.1)
    out += table.gc(2.0, force=True)
    return out


def test_out_of_order_and_retransmit():
    t = FlowTable(3000)
    a, b = REQ[:30], REQ[30:]
    resp = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}"
    out = feed_all(t, [(1030, b), (1000, a), (1000, a)], resp)
    assert len(out) == 1 and out[0].req.method == "POST" and out[0].resp.status == 201
    assert out[0].req.body == b'{"name":"a1"}'


def test_chunked_gzip_response():
    body = gzip.compress(json.dumps({"data": [1, 2, 3]}).encode())
    chunked = b"".join(b"%x\r\n%s\r\n" % (len(body[i:i + 7]), body[i:i + 7]) for i in range(0, len(body), 7)) + b"0\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\n" + chunked
    p = HttpParser(False)
    msgs = p.feed(resp[:40], 0.0) + p.feed(resp[40:], 0.1)
    assert len(msgs) == 1 and json.loads(msgs[0].body) == {"data": [1, 2, 3]}


def test_pipelining_and_head():
    p = HttpParser(True)
    two = b"GET /a HTTP/1.1\r\n\r\nGET /b?x=1 HTTP/1.1\r\n\r\n"
    assert [m.target for m in p.feed(two, 0.0)] == ["/a", "/b?x=1"]


def test_normalize_path():
    assert normalize_path("/api/incidents/12/comments") == "/api/incidents/{incident_id}/comments"
    assert normalize_path("/api/Products/") == "/api/Products/"
