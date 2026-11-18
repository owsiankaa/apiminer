"""Porównanie odpowiedzi (oryginał vs bliźniak) + semantyczna analiza rozbieżności dla pętli CEGIS."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .traffic import normalize_path, singularize

MAJOR = {"connection", "server_error", "missing_route", "status", "content_type", "missing_field", "type_mismatch"}
IMPORTANT_HEADERS = ("content-type", "location", "www-authenticate", "access-control-allow-origin", "x-total-count", "allow")


@dataclass
class Issue:
    kind: str
    path: str = ""
    detail: str = ""

    @property
    def severity(self) -> str:
        return "major" if self.kind in MAJOR else "minor"

    def as_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "severity": self.severity, "path": self.path, "detail": self.detail}


def jt(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "str"
    return "list" if isinstance(v, list) else "obj"


def diff_shapes(orig: Any, twin: Any, path: str = "$", out: Optional[List[Issue]] = None, depth: int = 0) -> List[Issue]:
    out = [] if out is None else out
    if depth > 8 or len(out) > 40:
        return out
    a, b = jt(orig), jt(twin)
    if a == "null" or b == "null":
        return out
    if a != b:
        out.append(Issue("type_mismatch", path, f"orig={a} twin={b}"))
    elif a == "obj":
        for k in orig:
            if k not in twin:
                out.append(Issue("missing_field", f"{path}.{k}", f"orig has {jt(orig[k])}"))
            else:
                diff_shapes(orig[k], twin[k], f"{path}.{k}", out, depth + 1)
        for k in twin:
            if k not in orig:
                out.append(Issue("extra_field", f"{path}.{k}", ""))
    elif a == "list":
        if orig and not twin:
            out.append(Issue("empty_list", path, "orig non-empty, twin empty"))
        elif orig and twin:
            diff_shapes(orig[0], twin[0], f"{path}[0]", out, depth + 1)
    return out


def body_kind(text: str, data: Any, ct: str) -> str:
    if data is not None:
        return "json"
    if text:
        return "html" if "html" in ct else "text"
    return "empty"


def make_resp(status: Any, headers: Dict[str, str], text: str = "", data: Any = None, tb: str = "") -> Dict[str, Any]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return {"status": status, "headers": h, "kind": body_kind(text, data, h.get("content-type", "")), "data": data, "text": text or "", "traceback": tb}


def resp_from_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    return make_resp(rec["status"], rec.get("headers") or {}, rec.get("body_text") or "", rec.get("body_json"))


def resp_from_requests(r) -> Dict[str, Any]:
    text = r.text or ""
    data = None
    if "json" in r.headers.get("content-type", "").lower() or text.lstrip()[:1] in ("{", "["):
        try:
            data = r.json()
        except ValueError:
            data = None
    return make_resp(r.status_code, dict(r.headers), text, data)


def compare(orig: Dict[str, Any], twin: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []
    so, st = orig["status"], twin["status"]
    if st == "CONN_ERR":
        return [Issue("connection", "", str(twin["text"])[:120])]
    if so != st:
        if isinstance(st, int) and st >= 500:
            issues.append(Issue("server_error", "", f"orig={so} twin={st}"))
        elif st in (404, 405) and so not in (404, 405):
            issues.append(Issue("missing_route", "", f"orig={so} twin={st}"))
        else:
            issues.append(Issue("status", "", f"orig={so} twin={st}"))
    if orig["kind"] != twin["kind"] and not (orig["kind"] == "empty" and twin["kind"] == "empty"):
        issues.append(Issue("content_type", "", f"orig={orig['kind']} twin={twin['kind']}"))
    elif orig["kind"] == "json":
        issues += diff_shapes(orig["data"], twin["data"])
    elif orig["kind"] == "text" and len(orig["text"]) < 200 and orig["text"].strip() != twin["text"].strip() and so == st:
        issues.append(Issue("text_body", "", f"orig={orig['text'][:60]!r} twin={twin['text'][:60]!r}"))
    for h in IMPORTANT_HEADERS:
        if h in orig["headers"] and h not in twin["headers"]:
            issues.append(Issue("header_missing", h, orig["headers"][h][:80]))
        elif h == "content-type" and h in orig["headers"] and h in twin["headers"]:
            if orig["headers"][h].lower().replace(" ", "") != twin["headers"][h].lower().replace(" ", ""):
                issues.append(Issue("header_value", h, f"orig={orig['headers'][h]} twin={twin['headers'][h]}"))
    return issues


def is_match(issues: List[Issue], strict: bool = False) -> bool:
    return not issues if strict else not any(i.severity == "major" for i in issues)


# --------------------------------------------------------------------------------------------------
# Generowanie przypadków testowych
# --------------------------------------------------------------------------------------------------
def cases_from_exchanges(exchanges: List[Dict[str, Any]], limit: int = 200) -> List[Dict[str, Any]]:
    seen, cases = set(), []
    for ex in exchanges:
        req = ex["request"]
        payload = req.get("body_json")
        key = (req["method"], req["path"], json.dumps(payload, sort_keys=True, default=str) if payload is not None else "")
        if key in seen:
            continue
        seen.add(key)
        h = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        hdr = {k: h[k] for k in ("authorization", "content-type", "accept") if k in h}
        cases.append({"method": req["method"], "path": req["path"], "payload": payload, "raw": None if payload is not None else req.get("body_text"),
                      "headers": hdr, "source": "observed", "expected": resp_from_record(ex["response"])})
        if len(cases) >= limit:
            break
    return cases


def derive_probe_cases(exchanges: List[Dict[str, Any]], limit: int = 60) -> List[Dict[str, Any]]:
    """Dodatkowe sondy: nieistniejące ID (404), puste/niekompletne payloady (walidacja)."""
    cases, seen = [], set()
    for ex in exchanges:
        req = ex["request"]
        tpl, method, path = ex["endpoint"], req["method"], req["path"].split("?")[0]
        h = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        hdr = {k: h[k] for k in ("authorization", "content-type") if k in h}
        if "{" in tpl and ("404", method, tpl) not in seen and method in ("GET", "PUT", "PATCH", "DELETE"):
            seen.add(("404", method, tpl))
            miss = re.sub(r"/\d+(?=/|$)", "/999999", path)
            if miss != path:
                cases.append({"method": method, "path": miss, "payload": req.get("body_json"), "raw": None, "headers": hdr, "source": "probe-404"})
        body = req.get("body_json")
        if method in ("POST", "PUT", "PATCH") and isinstance(body, dict) and body and ("empty", method, tpl) not in seen:
            seen.add(("empty", method, tpl))
            cases.append({"method": method, "path": path, "payload": {}, "raw": None, "headers": hdr, "source": "probe-empty"})
            first = next(iter(body))
            cases.append({"method": method, "path": path, "payload": {k: v for k, v in body.items() if k != first}, "raw": None, "headers": hdr, "source": f"probe-missing:{first}"})
        if len(cases) >= limit:
            break
    return cases


# --------------------------------------------------------------------------------------------------
# Analiza semantyczna
# --------------------------------------------------------------------------------------------------
TB_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"has no attribute '(\w+)'"), "Attribute '{0}' missing on ORM model/object: add Column '{0}' to the model (and schema) or guard the filter with hasattr()."),
    (re.compile(r"no such column: ([\w\.\"]+)"), "SQL refers to nonexistent column {0}: align Column definitions with schema.sql."),
    (re.compile(r"no such table: (\w+)"), "Table {0} does not exist: __tablename__ must equal the table name in schema.sql (case-sensitive)."),
    (re.compile(r"FOREIGN KEY constraint failed"), "FK violation: validate the parent row exists and return the observed 4xx, or ensure parent seed rows exist."),
    (re.compile(r"UNIQUE constraint failed: ([\w\.]+)"), "Unique violation on {0}: observed app likely returns 4xx/409 on duplicates or auto-generates the key."),
    (re.compile(r"NOT NULL constraint failed: ([\w\.]+)"), "NOT NULL failed on {0}: make the column nullable or supply a default from request/seed."),
    (re.compile(r"(\d+) validation errors? for (\w+)"), "Pydantic validation failure in model {1}: make nullable fields Optional[...] = None and loosen types to what the traffic shows."),
    (re.compile(r"DetachedInstanceError"), "Lazy relationship accessed after session closed: use selectinload()/joinedload() or serialize inside the session."),
    (re.compile(r"Unable to serialize|not JSON serializable|PydanticSerializationError"), "Serialization problem: use response models with ConfigDict(from_attributes=True) or convert datetime -> isoformat()."),
    (re.compile(r"ImportError|ModuleNotFoundError: No module named '(\w+)'"), "Missing import/module {0}: use only fastapi, pydantic v2, sqlalchemy 2.x and the stdlib."),
    (re.compile(r"NameError: name '(\w+)' is not defined"), "NameError: '{0}' is not defined/imported."),
    (re.compile(r"TypeError: (.{0,120})"), "TypeError: {0}"),
]


def parse_traceback(text: str) -> List[Dict[str, str]]:
    found, seen = [], set()
    for m in re.finditer(r'File "[^"]*main\.py", line (\d+), in (\w+)', text or ""):
        found.append({"main_py_line": m.group(1), "function": m.group(2)})
    hints = []
    for rx, tmpl in TB_RULES:
        for m in rx.finditer(text or ""):
            h = tmpl.format(*m.groups()) if m.groups() else tmpl
            if h not in seen:
                seen.add(h)
                hints.append(h)
    return [{"frame": f"main.py:{f['main_py_line']} in {f['function']}"} for f in found[-4:]] + [{"hint": h} for h in hints[:8]]


def _fk_hint(field: str, known_tables: List[str]) -> Optional[str]:
    m = re.match(r"^(.+?)(?:_id|Id|ID)$", field)
    if not m:
        return None
    base = singularize(m.group(1))
    for t in known_tables:
        if singularize(t) == base:
            return f"Field '{field}' looks like a foreign key -> table '{t}': add ForeignKey('{t}.id') + relationship and include '{field}' in response/request models."
    return f"Field '{field}' looks like a foreign key to a '{m.group(1)}' resource not yet modeled: add Column(Integer, nullable=True) and (optionally) a stub table."


def analyze_cases(cases: List[Dict[str, Any]], twin_logs: str = "", known_tables: Optional[List[str]] = None) -> Dict[str, Any]:
    known_tables = known_tables or []
    by_kind: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in cases:
        for i in c.get("issues", []):
            by_kind[i["kind"]].append({"case": c, "issue": i})
    hints: List[str] = []

    for item in by_kind.get("missing_route", []):
        c = item["case"]
        tpl = normalize_path(c["path"])
        segs = [s for s in tpl.strip("/").split("/") if s]
        nested = len(segs) >= 3 and segs[-1][0] != "{" and any(s.startswith("{") for s in segs[:-1])
        if nested:
            parent = next((segs[i - 1] for i in range(len(segs) - 1, 0, -1) if segs[i].startswith("{")), "")
            hints.append(f"Missing nested route {c['method']} {tpl}: add it; child rows must carry FK to '{parent}' (ForeignKey + relationship) and be filtered by the path id.")
        elif c["method"] != "GET":
            hints.append(f"Missing {c['method']} {tpl} (twin answered {item['issue']['detail']}): route may exist with another method or path slash - match exactly (redirect_slashes=False).")
        else:
            hints.append(f"Missing GET {tpl}: implement with the observed response shape.")
    for item in by_kind.get("server_error", []):
        tb = parse_traceback(item["case"].get("twin_traceback", ""))
        hints += [t["hint"] for t in tb if "hint" in t]
    if twin_logs:
        hints += [t["hint"] for t in parse_traceback(twin_logs) if "hint" in t]
    for item in by_kind.get("status", []):
        c, d = item["case"], item["issue"]["detail"]
        m = re.search(r"orig=(\S+) twin=(\S+)", d)
        if not m:
            continue
        o, t = m.groups()
        tpl = normalize_path(c["path"])
        if o == "201":
            hints.append(f"{c['method']} {tpl}: original returns 201 -> set status_code=201.")
        elif o in ("401", "403"):
            hints.append(f"{c['method']} {tpl}: original returns {o} for this request -> implement auth check / same failure branch.")
        elif o == "404" and t in ("200", "201"):
            hints.append(f"{c['method']} {tpl}: unknown id must return 404 in the observed body format.")
        elif o in ("400", "422") and t in ("200", "201"):
            hints.append(f"{c['method']} {tpl}: validation expected to fail with {o} for source={c['source']} (empty/missing fields).")
        elif t in ("400", "422") and o.startswith("2"):
            hints.append(f"{c['method']} {tpl}: twin too strict (got {t}, expected {o}): make request-model fields Optional / accept the observed payload.")
        else:
            hints.append(f"{c['method']} {tpl}: status expected {o}, got {t}.")
    seen_fields = set()
    for item in by_kind.get("missing_field", []):
        path = item["issue"]["path"]
        name = path.split(".")[-1]
        if name in seen_fields:
            continue
        seen_fields.add(name)
        fk = _fk_hint(name, known_tables)
        hints.append(fk or f"Response field '{path}' missing: add it to the response model / DB column ({item['issue']['detail']}).")
    for item in by_kind.get("type_mismatch", [])[:6]:
        hints.append(f"Type mismatch at {item['issue']['path']} ({item['issue']['detail']}): fix Pydantic/SQLAlchemy type or JSON column handling; nested objects need nested models (from_attributes).")
    for item in by_kind.get("empty_list", [])[:4]:
        hints.append(f"List at {item['issue']['path']} empty in twin but not in original: seed rows / filter logic too strict.")
    for item in by_kind.get("header_missing", [])[:4]:
        hints.append(f"Header '{item['issue']['path']}' missing (orig: {item['issue']['detail']}): add via Response headers.")
    if by_kind.get("content_type"):
        c = by_kind["content_type"][0]
        hints.append(f"Body kind differs for {c['case']['method']} {normalize_path(c['case']['path'])} ({c['issue']['detail']}): return PlainTextResponse/HTMLResponse/JSONResponse exactly as original.")

    dedup = list(dict.fromkeys(hints))
    return {
        "counts": {k: len(v) for k, v in sorted(by_kind.items(), key=lambda kv: -len(kv[1]))},
        "hints": dedup[:25],
        "worst_cases": [
            {"req": f"{c['method']} {c['path']}", "source": c["source"], "payload": c.get("payload"),
             "issues": c["issues"][:4], "expected": _brief(c.get("expected")), "actual": _brief(c.get("actual"))}
            for c in sorted((c for c in cases if any(i["severity"] == "major" for i in c.get("issues", []))),
                            key=lambda c: -len(c["issues"]))[:12]
        ],
    }


def _brief(r: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not r:
        return None
    body = json.dumps(r["data"], ensure_ascii=False)[:220] if r["kind"] == "json" else (r["text"] or "")[:160]
    return {"status": r["status"], "kind": r["kind"], "body": body}


def render_analysis(a: Dict[str, Any], max_chars: int = 7000) -> str:
    L = ["ISSUE COUNTS: " + json.dumps(a["counts"]), "", "AUTO-DERIVED HINTS (most important first):"]
    L += [f"- {h}" for h in a["hints"]]
    L += ["", "WORST COUNTEREXAMPLES:"]
    for w in a["worst_cases"]:
        L.append(f"* {w['req']} [{w['source']}] payload={json.dumps(w['payload'], ensure_ascii=False)[:120]}")
        L.append(f"    issues: {json.dumps([i['kind'] + ':' + i['path'] + ' ' + i['detail'] for i in w['issues']], ensure_ascii=False)[:300]}")
        L.append(f"    expected: {json.dumps(w['expected'], ensure_ascii=False)[:300]}")
        L.append(f"    actual:   {json.dumps(w['actual'], ensure_ascii=False)[:300]}")
    text = "\n".join(L)
    return text if len(text) <= max_chars else text[:max_chars] + "\n...[truncated]"


def score(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = max(1, len(cases))
    lenient = sum(1 for c in cases if is_match([Issue(**{k: i[k] for k in ("kind", "path", "detail")}) for i in c.get("issues", [])]))
    strict = sum(1 for c in cases if not c.get("issues"))
    kinds = Counter(i["kind"] for c in cases for i in c.get("issues", []))
    return {"cases": len(cases), "lenient_match": lenient, "strict_match": strict, "lenient_pct": round(100 * lenient / n, 2),
            "strict_pct": round(100 * strict / n, 2), "issue_kinds": dict(kinds)}
