"""Wspólne narzędzia do pracy z przechwyconym ruchem: normalizacja ścieżek, klasyfikacja, (de)serializacja wymian HTTP."""
from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import parse_qsl, urlsplit

MAX_TEXT_BODY = int(os.getenv("MAX_BODY_BYTES", str(1 << 20)))

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
OID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.=]{24,}$")
INT_RE = re.compile(r"^\d+$")
STATIC_EXT = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3|wasm|html?)$", re.I
)
API_PREFIX = re.compile(r"^/(?:api|rest|graphql|v\d+|odata|trpc)(?:/|$)", re.I)


def singularize(word: str) -> str:
    w = word.lower()
    if len(w) <= 3:
        return w
    if w.endswith("ies"):
        return w[:-3] + "y"
    if w.endswith(("sses", "xes", "ches", "shes")):
        return w[:-2]
    if w.endswith("ss") or w.endswith("us") or w.endswith("is"):
        return w
    if w.endswith("s"):
        return w[:-1]
    return w


def normalize_name(word: str) -> str:
    return singularize(re.sub(r"[^a-z0-9]", "", word.lower()))


def normalize_path(path: str) -> str:
    """/api/items/5/comments -> /api/items/{item_id}/comments (zachowuje końcowy slash)."""
    p = path.split("?", 1)[0].split("#", 1)[0]
    if p in ("", "/"):
        return "/"
    trailing = p.endswith("/")
    out: List[str] = []
    used: set = set()
    prev_static = ""
    for seg in (s for s in p.split("/") if s):
        kind = None
        if INT_RE.match(seg) or UUID_RE.match(seg) or OID_RE.match(seg):
            kind = "id"
        elif HEX_RE.match(seg) or (TOKEN_RE.match(seg) and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg)):
            kind = "token"
        if kind is None:
            out.append(seg)
            prev_static = seg
            continue
        base = re.sub(r"[^A-Za-z0-9]+", "_", singularize(prev_static)).strip("_") if prev_static else ""
        name = f"{base}_{kind}" if base else kind
        n, cand = 2, name
        while cand in used:
            cand = f"{name}{n}"
            n += 1
        used.add(cand)
        out.append("{" + cand + "}")
    return "/" + "/".join(out) + ("/" if trailing else "")


def parse_query(path: str) -> Dict[str, str]:
    return dict(parse_qsl(urlsplit(path).query, keep_blank_values=True))


STATIC_PREFIX = ("/assets/", "/static/", "/i18n/", "/public/", "/dist/", "/_next/static/", "/node_modules/")
STATIC_CT = ("text/html", "text/css", "image/", "font/", "video/", "audio/", "application/font", "application/wasm")


def classify(method: str, path: str, resp_headers: Optional[Dict[str, str]]) -> str:
    p = path.split("?", 1)[0]
    ct = ((resp_headers or {}).get("content-type") or "").lower()
    if p.startswith("/socket.io"):
        return "other"
    # twarde sygnały pliku statycznego mają pierwszeństwo (np. image/svg+xml zawiera "xml", /assets/i18n/en.json jest JSON-em)
    if (ct.startswith(STATIC_CT[1:]) or "javascript" in ct or STATIC_EXT.search(p)
            or any(p.startswith(x) or x in p for x in STATIC_PREFIX)):
        return "static"
    if any(x in ct for x in ("json", "xml", "x-ndjson", "graphql")):
        return "api"
    if API_PREFIX.match(p):
        return "api"
    if ct.startswith("text/html"):
        return "static"
    if method.upper() not in ("GET", "HEAD"):
        return "api"
    return "other"


def message_view(msg, keep_body: bool = True) -> Dict[str, Any]:
    """HttpMessage -> słownik JSON-owalny."""
    ct = (msg.headers.get("content-type") or "").lower()
    view: Dict[str, Any] = {
        "headers": msg.headers,
        "body_len": msg.wire_len,
        "decoded_len": len(msg.body),
        "truncated": msg.truncated,
        "incomplete": msg.incomplete,
        "gap": msg.gap,
        "encoding_note": msg.encoding_note or None,
    }
    if msg.is_request:
        view.update(method=msg.method, path=msg.target, version=msg.version, query=parse_query(msg.target))
    else:
        view.update(status=msg.status, reason=msg.reason, version=msg.version)
    if not keep_body or not msg.body:
        return view
    textual = any(x in ct for x in ("json", "text", "xml", "x-www-form-urlencoded", "javascript")) or not ct
    if textual and len(msg.body) <= MAX_TEXT_BODY:
        text = msg.body.decode("utf-8", errors="replace")
        view["body_text"] = text
        stripped = text.lstrip()
        if "json" in ct or stripped[:1] in ("{", "["):
            try:
                view["body_json"] = json.loads(text)
            except ValueError:
                pass
        elif "x-www-form-urlencoded" in ct:
            view["body_form"] = dict(parse_qsl(text, keep_blank_values=True))
    elif len(msg.body) <= 4096:
        view["body_b64"] = base64.b64encode(msg.body).decode()
    return view


def exchange_to_record(ex_id: int, conn_label: str, req, resp, latency_us: Optional[int]) -> Dict[str, Any]:
    kind = classify(req.method, req.target, resp.headers if resp else None)
    keep = kind != "static"
    return {
        "id": ex_id,
        "conn": conn_label,
        "ts": req.ts,
        "latency_us": latency_us,
        "kind": kind,
        "endpoint": normalize_path(req.target),
        "request": message_view(req, keep),
        "response": message_view(resp, keep) if resp else None,
    }


def read_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def load_exchanges(path: str, kinds=("api",)) -> List[Dict[str, Any]]:
    """Wczytuje wymiany i reklasyfikuje je bieżącą heurystyką (można poprawiać klasyfikację bez ponownego zbierania ruchu)."""
    out = []
    for r in read_jsonl(path):
        resp = r.get("response")
        if not resp:
            continue
        r["kind"] = classify(r["request"].get("method", "GET"), r["request"].get("path", ""), resp.get("headers"))
        if r["kind"] in kinds:
            out.append(r)
    return out
