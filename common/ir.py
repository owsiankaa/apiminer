"""Deterministyczna inferencja kontraktu API (IR): operacje, zasoby, klucze obce, DDL, OpenAPI 3.1, seedy, nagłówki, auth.

LLM dostaje to jako *priora* (digest) – nie musi zgadywać tego, co da się wyliczyć z ruchu.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .traffic import normalize_name, singularize

PREFIX_SEGS = {"api", "rest", "public", "internal", "service", "services"}
LISTING_ACTIONS = {"search", "list", "all", "query", "filter", "find"}
ACTION_WORDS = LISTING_ACTIONS | {
    "login", "logout", "register", "signup", "signin", "verify", "count", "export", "import", "status", "state",
    "whoami", "reset", "refresh", "upload", "download", "me", "current", "stats", "summary", "health", "version",
    "application-version", "authenticate", "token", "callback", "check", "validate", "confirm", "activate",
}
ENVELOPE_KEYS = ("data", "items", "results", "rows", "content", "records", "value", "list")
TOKEN_KEYS = {"token", "access_token", "accesstoken", "jwt", "id_token", "idtoken", "authtoken", "bearer"}
DYNAMIC_HEADERS = {
    "date", "content-length", "connection", "keep-alive", "etag", "set-cookie", "transfer-encoding", "last-modified",
    "content-type", "content-encoding", "location", "server", "www-authenticate", "retry-after", "age", "expires",
}
DYNAMIC_HEADER_RE = re.compile(r"request-id|trace|correlation|nonce|csrf|token|session|ratelimit|rate-limit|timing")

FORMAT_RES = [
    ("date-time", re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("uuid", re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")),
    ("uri", re.compile(r"^https?://\S+$")),
]


# --------------------------------------------------------------------------------------------------
# JSON Schema
# --------------------------------------------------------------------------------------------------
def jtype(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "string"


def detect_format(s: str) -> Optional[str]:
    for name, rx in FORMAT_RES:
        if rx.match(s):
            return name
    return None


def infer_schema(samples: List[Any], depth: int = 0, max_depth: int = 6) -> Dict[str, Any]:
    if not samples:
        return {}
    kinds = {jtype(s) for s in samples}
    nullable = "null" in kinds
    kinds.discard("null")
    if kinds == {"integer", "number"}:
        kinds = {"number"}
    if not kinds:
        return {"type": "null"}
    if len(kinds) > 1:
        return {"type": sorted(kinds) + (["null"] if nullable else [])}
    k = next(iter(kinds))
    nn = [s for s in samples if s is not None]
    sch: Dict[str, Any] = {"type": [k, "null"] if nullable else k}
    if k == "object" and depth < max_depth:
        keys: List[str] = []
        vals: Dict[str, List[Any]] = defaultdict(list)
        for o in nn:
            for kk, vv in o.items():
                if kk not in vals:
                    keys.append(kk)
                vals[kk].append(vv)
        sch["properties"] = {kk: infer_schema(vals[kk], depth + 1, max_depth) for kk in keys}
        req = [kk for kk in keys if len(vals[kk]) == len(nn)]
        if req:
            sch["required"] = req
    elif k == "array" and depth < max_depth:
        items = [x for a in nn for x in a[:50]]
        if items:
            sch["items"] = infer_schema(items, depth + 1, max_depth)
    elif k == "string":
        fmts = {detect_format(s) for s in nn}
        if len(fmts) == 1 and None not in fmts:
            sch["format"] = next(iter(fmts))
        distinct = set(nn)
        if len(nn) >= 6 and len(distinct) <= 5 and all(len(s) <= 40 for s in distinct):
            sch["enum"] = sorted(distinct)
    if nn and k in ("string", "integer", "number", "boolean"):
        ex = nn[0]
        sch["example"] = ex[:80] if isinstance(ex, str) else ex
    return sch


def schema_to_str(s: Dict[str, Any], depth: int = 0) -> str:
    if not s:
        return "any"
    t = s.get("type")
    tt = "|".join(t) if isinstance(t, list) else (t or "any")
    base = tt.split("|")[0] if isinstance(t, list) else tt
    if base == "object":
        props = s.get("properties", {})
        if depth >= 3:
            return "{...}"
        req = set(s.get("required", []))
        items = [f"{k}{'' if k in req else '?'}:{schema_to_str(v, depth + 1)}" for k, v in list(props.items())[:30]]
        return "{" + ", ".join(items) + "}"
    if base == "array":
        return "[" + schema_to_str(s.get("items", {}), depth + 1) + "]"
    out = tt
    if s.get("format"):
        out += f"({s['format']})"
    if s.get("enum"):
        out += "{" + "|".join(map(str, s["enum"])) + "}"
    return out


# --------------------------------------------------------------------------------------------------
# Struktury
# --------------------------------------------------------------------------------------------------
@dataclass
class Operation:
    method: str
    template: str
    count: int = 0
    paths: List[str] = field(default_factory=list)
    query: Dict[str, List[str]] = field(default_factory=dict)
    req_ct: Optional[str] = None
    req_samples: List[Any] = field(default_factory=list)
    responses: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    auth_sent: int = 0
    noauth_status: Counter = field(default_factory=Counter)
    resource: Optional[str] = None
    action: Optional[str] = None
    parent: Optional[str] = None
    parent_param: Optional[str] = None
    is_item: bool = False
    rpc: bool = False

    @property
    def key(self) -> str:
        return f"{self.method} {self.template}"

    @property
    def protected(self) -> Optional[bool]:
        if any(s in (401, 403) for s in self.noauth_status):
            return True
        if any(200 <= s < 300 for s in self.noauth_status):
            return False
        return None

    def req_schema(self) -> Dict[str, Any]:
        return infer_schema(self.req_samples) if self.req_samples else {}


@dataclass
class Column:
    name: str
    sql_type: str = "TEXT"
    pk: bool = False
    fk: Optional[Tuple[str, str]] = None
    fk_verified: bool = False
    writable: bool = False


@dataclass
class Resource:
    name: str
    key: str
    columns: Dict[str, Column] = field(default_factory=dict)
    rows: List[Dict[str, Any]] = field(default_factory=list)
    pk: Optional[str] = None
    env_list: Optional[Dict[str, Any]] = None
    env_item: Optional[Dict[str, Any]] = None
    ops: List[str] = field(default_factory=list)
    parent_links: set = field(default_factory=set)
    values: Dict[str, List[Any]] = field(default_factory=lambda: defaultdict(list))
    writable: set = field(default_factory=set)


def resource_info(template: str) -> Dict[str, Any]:
    segs = [s for s in template.strip("/").split("/") if s]
    while segs and (segs[0].lower() in PREFIX_SEGS or re.fullmatch(r"v\d+", segs[0].lower())):
        segs.pop(0)
    statics: List[Tuple[str, Optional[str]]] = []
    for s in segs:
        if s.startswith("{"):
            if statics:
                statics[-1] = (statics[-1][0], s.strip("{}"))
        else:
            statics.append((s, None))
    names = [n for n, _ in statics]
    nouns = [(n, p) for n, p in statics if n.lower() not in ACTION_WORDS]
    action = names[-1] if names and names[-1].lower() in ACTION_WORDS else None
    resource = nouns[-1][0] if nouns else None
    parent, parent_param = (nouns[-2] if len(nouns) >= 2 else (None, None))
    has_param = "{" in template
    rpc = bool(action) and action.lower() not in LISTING_ACTIONS and not has_param
    is_item = bool(statics) and any(p for n, p in statics if n == resource) if resource else False
    return {"resource": resource, "action": action, "parent": parent, "parent_param": parent_param, "rpc": rpc, "is_item": is_item}


def unwrap_entities(body: Any) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)], None
    if isinstance(body, dict):
        for k in ENVELOPE_KEYS:
            v = body.get(k)
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                meta = {kk: vv for kk, vv in body.items() if kk != k and not isinstance(vv, (dict, list))}
                return v, {"key": k, "meta": meta}
            if isinstance(v, list) and not v and len(body) <= 4:
                return [], {"key": k, "meta": {kk: vv for kk, vv in body.items() if kk != k and not isinstance(vv, (dict, list))}}
            if isinstance(v, dict) and len(body) <= 4:
                meta = {kk: vv for kk, vv in body.items() if kk != k and not isinstance(vv, (dict, list))}
                return [v], {"key": k, "meta": meta, "single": True}
        return [body], None
    return [], None


def is_entity(e: Dict[str, Any]) -> bool:
    return len(e) >= 2 and any(not isinstance(v, (dict, list)) for v in e.values())


def find_key_path(obj: Any, names: set, prefix: str = "", depth: int = 0) -> Optional[str]:
    if depth > 5:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in names and isinstance(v, str) and len(v) > 16:
                return f"{prefix}{k}"
        for k, v in obj.items():
            r = find_key_path(v, names, f"{prefix}{k}.", depth + 1)
            if r:
                return r
    return None


# --------------------------------------------------------------------------------------------------
# Budowa modelu
# --------------------------------------------------------------------------------------------------
def build_operations(exchanges: List[Dict[str, Any]]) -> Dict[str, Operation]:
    ops: Dict[str, Operation] = {}
    for ex in exchanges:
        req, resp = ex["request"], ex["response"]
        method = req.get("method", "GET")
        op = ops.setdefault(f"{method} {ex['endpoint']}", Operation(method, ex["endpoint"]))
        op.count += 1
        path = req.get("path", "")
        if path not in op.paths and len(op.paths) < 5:
            op.paths.append(path)
        for k, v in (req.get("query") or {}).items():
            ex_list = op.query.setdefault(k, [])
            if v not in ex_list and len(ex_list) < 4:
                ex_list.append(v)
        h = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        has_auth = "authorization" in h
        op.auth_sent += int(has_auth)
        if not has_auth:
            op.noauth_status[resp["status"]] += 1
        if req.get("body_json") is not None and len(op.req_samples) < 12:
            op.req_samples.append(req["body_json"])
            op.req_ct = h.get("content-type", op.req_ct)
        elif req.get("body_form") and len(op.req_samples) < 12:
            op.req_samples.append(req["body_form"])
            op.req_ct = h.get("content-type", op.req_ct)
        slot = op.responses.setdefault(
            resp["status"], {"count": 0, "samples": [], "texts": [], "content_type": None, "headers": Counter()}
        )
        slot["count"] += 1
        rh = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        slot["content_type"] = rh.get("content-type", slot["content_type"])
        if resp.get("body_json") is not None and len(slot["samples"]) < 10:
            slot["samples"].append(resp["body_json"])
        elif resp.get("body_text") and len(slot["texts"]) < 3:
            slot["texts"].append(resp["body_text"][:300])
    for op in ops.values():
        info = resource_info(op.template)
        op.resource, op.action, op.parent, op.parent_param = info["resource"], info["action"], info["parent"], info["parent_param"]
        op.is_item, op.rpc = info["is_item"], info["rpc"]
    return ops


def build_resources(ops: Dict[str, Operation]) -> Dict[str, Resource]:
    res: Dict[str, Resource] = {}

    def get(name: str) -> Resource:
        key = normalize_name(name)
        if key not in res:
            res[key] = Resource(name=name, key=key)
        return res[key]

    for op in sorted(ops.values(), key=lambda o: -o.count):
        if not op.resource or op.rpc:
            continue
        r = get(op.resource)
        r.ops.append(op.key)
        if op.parent and op.parent_param:
            r.parent_links.add((op.parent_param, op.parent))
        for status, slot in op.responses.items():
            if not 200 <= status < 300:
                continue
            for body in slot["samples"]:
                ents, env = unwrap_entities(body)
                ents = [e for e in ents if is_entity(e)]
                if env and not env.get("single") and op.method == "GET" and not op.is_item and not r.env_list:
                    r.env_list = env
                if env and env.get("single") and not r.env_item:
                    r.env_item = env
                for e in ents:
                    r.rows.append(e)
                    for k, v in e.items():
                        r.values[k].append(v)
        if op.method in ("POST", "PUT", "PATCH"):
            for body in op.req_samples:
                if isinstance(body, dict):
                    for k, v in body.items():
                        r.values[k].append(v)
                        r.writable.add(k)

    sql_types = {"integer": "INTEGER", "number": "REAL", "boolean": "BOOLEAN", "string": "TEXT", "array": "JSON", "object": "JSON"}
    for r in res.values():
        for col, vals in r.values.items():
            kinds = {jtype(v) for v in vals if v is not None} or {"string"}
            if kinds == {"integer", "number"}:
                kinds = {"number"}
            t = sql_types[next(iter(kinds))] if len(kinds) == 1 else "TEXT"
            r.columns[col] = Column(col, t, writable=col in r.writable)
        sing = singularize(r.name)
        for cand in ("id", f"{sing}id", f"{sing}_id"):
            hit = next((c for c in r.columns if c.lower() == cand), None)
            if hit:
                r.pk = hit
                r.columns[hit].pk = True
                break
    # klucze obce
    for r in res.values():
        for c in list(r.columns.values()):
            if c.pk:
                continue
            m = re.match(r"^(.+?)(?:_id|Id|ID)$", c.name)
            if not m:
                continue
            ref = res.get(normalize_name(m.group(1)))
            if ref and ref is not r:
                ref_pk = ref.pk or "id"
                ids = {json.dumps(v) for rr in ref.rows for v in [rr.get(ref_pk)] if v is not None}
                mine = {json.dumps(v) for v in r.values[c.name] if v is not None}
                c.fk, c.fk_verified = (ref.name, ref_pk), bool(mine) and bool(ids) and mine <= ids
        for param, parent in sorted(r.parent_links):
            ref = res.get(normalize_name(parent))
            if ref and ref is not r:
                col = r.columns.get(param) or r.columns.setdefault(param, Column(param, "INTEGER"))
                if not col.fk:
                    col.fk, col.fk_verified = (ref.name, ref.pk or "id"), False
    return res


def to_ddl(resources: Dict[str, Resource]) -> str:
    deps = {r.name: {c.fk[0] for c in r.columns.values() if c.fk and c.fk[0] != r.name} for r in resources.values()}
    ordered: List[str] = []
    seen: set = set()

    def visit(n: str, stack: Tuple[str, ...] = ()) -> None:
        if n in seen or n in stack:
            return
        for d in deps.get(n, ()):
            visit(d, stack + (n,))
        seen.add(n)
        ordered.append(n)

    for n in deps:
        visit(n)
    by_name = {r.name: r for r in resources.values()}
    out = []
    for n in ordered:
        r = by_name[n]
        if not r.columns:
            continue
        lines = []
        for c in r.columns.values():
            line = f'  "{c.name}" {c.sql_type}'
            if c.pk:
                line += " PRIMARY KEY" + (" AUTOINCREMENT" if c.sql_type == "INTEGER" else "")
            lines.append(line)
        for c in r.columns.values():
            if c.fk and c.fk[0] in by_name:
                lines.append(f'  FOREIGN KEY ("{c.name}") REFERENCES "{c.fk[0]}"("{c.fk[1]}")')
        out.append(f'CREATE TABLE "{r.name}" (\n' + ",\n".join(lines) + "\n);\n")
    return "\n".join(out)


def build_seed(resources: Dict[str, Resource], cap: int = 200) -> Dict[str, List[Dict[str, Any]]]:
    seed: Dict[str, List[Dict[str, Any]]] = {}
    for r in resources.values():
        merged: Dict[str, Dict[str, Any]] = {}
        for row in r.rows:
            key = json.dumps(row.get(r.pk), default=str) if r.pk and r.pk in row else json.dumps(row, sort_keys=True, default=str)
            merged.setdefault(key, {}).update(row)
        if merged:
            seed[r.name] = list(merged.values())[:cap]
    return seed


def constant_headers(exchanges: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(exchanges)
    counts: Dict[str, Counter] = defaultdict(Counter)
    ct_json: Counter = Counter()
    val_status: Counter = Counter()
    for ex in exchanges:
        resp = ex["response"]
        for k, v in (resp.get("headers") or {}).items():
            counts[k.lower()][v] += 1
            if k.lower() == "content-type" and "json" in v.lower():
                ct_json[v] += 1
        if ex["request"].get("method") in ("POST", "PUT", "PATCH") and resp["status"] in (400, 422):
            val_status[resp["status"]] += 1
    const: Dict[str, str] = {}
    if n >= 3:
        for h, c in counts.items():
            if h in DYNAMIC_HEADERS or DYNAMIC_HEADER_RE.search(h):
                continue
            val, hits = c.most_common(1)[0]
            if sum(c.values()) >= 0.9 * n and hits >= 0.9 * sum(c.values()):
                const[h] = val
    return {
        "constant": const,
        "json_content_type": ct_json.most_common(1)[0][0] if ct_json else None,
        "validation_status": val_status.most_common(1)[0][0] if val_status else 422,
    }


def detect_auth(ops: Dict[str, Operation], exchanges: List[Dict[str, Any]]) -> Dict[str, Any]:
    scheme = None
    for ex in exchanges:
        h = {k.lower(): v for k, v in (ex["request"].get("headers") or {}).items()}
        a = h.get("authorization", "")
        if a.lower().startswith("bearer "):
            scheme = "bearer"
            break
        if a.lower().startswith("basic "):
            scheme = "basic"
    if scheme is None and any("cookie" in {k.lower() for k in (ex["request"].get("headers") or {})} for ex in exchanges):
        scheme = "cookie"
    logins = []
    for op in ops.values():
        if op.method != "POST":
            continue
        for status, slot in op.responses.items():
            if 200 <= status < 300:
                for body in slot["samples"]:
                    path = find_key_path(body, TOKEN_KEYS)
                    if path:
                        fields = sorted({k for s in op.req_samples if isinstance(s, dict) for k in s})
                        logins.append({"endpoint": op.key, "request_fields": fields, "token_path": path})
                        break
    protected = sorted(o.key for o in ops.values() if o.protected)
    return {"scheme": scheme, "login": logins[:3], "protected_ops": protected[:40]}


# --------------------------------------------------------------------------------------------------
# Model zbiorczy
# --------------------------------------------------------------------------------------------------
class ApiModel:
    def __init__(self, exchanges: List[Dict[str, Any]], static_hints: Optional[List[str]] = None):
        self.exchanges = exchanges
        self.ops = build_operations(exchanges)
        self.resources = {k: r for k, r in build_resources(self.ops).items() if 0 < len(r.columns) <= 80}
        self.headers_cfg = constant_headers(exchanges)
        self.auth = detect_auth(self.ops, exchanges)
        self.static_hints = static_hints or []

    # --- artefakty
    def ddl(self) -> str:
        return to_ddl(self.resources)

    def seed(self) -> Dict[str, List[Dict[str, Any]]]:
        return build_seed(self.resources)

    def openapi(self) -> Dict[str, Any]:
        paths: Dict[str, Dict[str, Any]] = {}
        for op in sorted(self.ops.values(), key=lambda o: (o.template, o.method)):
            params = [
                {"name": m, "in": "path", "required": True, "schema": {"type": "integer" if m.endswith(("_id", "id")) else "string"}}
                for m in re.findall(r"\{([^}]+)\}", op.template)
            ]
            params += [{"name": q, "in": "query", "required": False, "schema": {"type": "string"}, "example": ex[0] if ex else ""} for q, ex in op.query.items()]
            entry: Dict[str, Any] = {"operationId": re.sub(r"\W+", "_", f"{op.method.lower()}{op.template}").strip("_"), "responses": {}}
            if params:
                entry["parameters"] = params
            if op.req_samples:
                entry["requestBody"] = {"content": {(op.req_ct or "application/json").split(";")[0]: {"schema": op.req_schema()}}}
            for status, slot in sorted(op.responses.items()):
                r: Dict[str, Any] = {"description": f"observed x{slot['count']}"}
                if slot["samples"]:
                    ct = (slot["content_type"] or "application/json").split(";")[0]
                    r["content"] = {ct: {"schema": infer_schema(slot["samples"])}}
                elif slot["texts"]:
                    r["content"] = {(slot["content_type"] or "text/plain").split(";")[0]: {"schema": {"type": "string"}, "example": slot["texts"][0]}}
                entry["responses"][str(status)] = r
            if op.protected:
                entry["security"] = [{"auth": []}]
            paths.setdefault(op.template, {})[op.method.lower()] = entry
        spec: Dict[str, Any] = {"openapi": "3.1.0", "info": {"title": "Synthesized API (black-box)", "version": "0.1.0"}, "paths": paths}
        if self.auth["scheme"] in ("bearer", "basic"):
            spec["components"] = {"securitySchemes": {"auth": {"type": "http", "scheme": self.auth["scheme"]}}}
        return spec

    def digest(self, budget_chars: int = 14000, examples: int = 10) -> str:
        L: List[str] = ["# GLOBAL"]
        L.append(f"auth: {self.auth['scheme'] or 'none-observed'}")
        for lg in self.auth["login"]:
            L.append(f"login: {lg['endpoint']} fields={lg['request_fields']} token_at={lg['token_path']}")
        L.append(f"json_content_type: {self.headers_cfg['json_content_type']}")
        L.append(f"validation_error_status: {self.headers_cfg['validation_status']}")
        L.append("\n# RESOURCES (tables; __tablename__ must equal these names)")
        for r in self.resources.values():
            cols = ", ".join(f"{c.name}:{c.sql_type}{'*' if c.pk else ''}" for c in r.columns.values())
            fks = "; ".join(f"{c.name}->{c.fk[0]}.{c.fk[1]}({'verified' if c.fk_verified else 'guess'})" for c in r.columns.values() if c.fk)
            L.append(f"{r.name}: [{cols}]" + (f" FK: {fks}" if fks else ""))
            if r.env_list:
                L.append(f"  list_envelope: key={r.env_list['key']} meta={json.dumps(r.env_list['meta'], ensure_ascii=False)}")
            if r.env_item:
                L.append(f"  item_envelope: key={r.env_item['key']} meta={json.dumps(r.env_item['meta'], ensure_ascii=False)}")
        L.append("\n# OPERATIONS (METHOD template | auth | query | request | responses)")
        used = sum(len(x) for x in L)
        for i, op in enumerate(sorted(self.ops.values(), key=lambda o: -o.count)):
            prot = {True: "auth-required", False: "public", None: "auth-unknown"}[op.protected]
            line = f"{op.key} | {prot}"
            if op.query:
                line += " | query: " + ",".join(f"{k}={v[0]!r}" for k, v in op.query.items())
            if op.req_samples:
                line += " | req: " + schema_to_str(op.req_schema())
            for status, slot in sorted(op.responses.items()):
                if slot["samples"]:
                    line += f"\n    {status} -> {schema_to_str(infer_schema(slot['samples']))}"
                    if i < examples:
                        line += "\n      e.g. " + json.dumps(compact_json(slot["samples"][0]), ensure_ascii=False)[:500]
                elif slot["texts"]:
                    line += f"\n    {status} -> text {slot['texts'][0][:100]!r}"
                else:
                    line += f"\n    {status} -> (empty)"
            if used + len(line) > budget_chars:
                L.append(f"... ({len(self.ops) - i} more operations truncated)")
                break
            used += len(line)
            L.append(line)
        if self.static_hints:
            L.append("\n# HINTS: endpoints referenced in frontend JS but never observed (unverified)")
            L += [f"  {h}" for h in self.static_hints[:25]]
        return "\n".join(L)

    def summary(self) -> Dict[str, Any]:
        return {
            "exchanges": len(self.exchanges),
            "operations": len(self.ops),
            "resources": {r.name: len(r.columns) for r in self.resources.values()},
            "fks": sum(1 for r in self.resources.values() for c in r.columns.values() if c.fk),
            "auth": self.auth["scheme"],
        }


def compact_json(val: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "..."
    if isinstance(val, list):
        return [compact_json(x, depth + 1) for x in val[:2]]
    if isinstance(val, dict):
        return {k: compact_json(v, depth + 1) for k, v in list(val.items())[:25]}
    if isinstance(val, str) and len(val) > 100:
        return val[:100] + "..."
    return val
