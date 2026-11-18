"""Rejestr zasobów (uczony z odpowiedzi API) + generator wartości pól świadomy kluczy obcych i błędów walidacji."""
from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from datetime import date, datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from common.ir import resource_info, unwrap_entities  # noqa: E402
from common.traffic import normalize_name, normalize_path  # noqa: E402

FK_RE = re.compile(r"^(.+?)(?:_id|Id|ID)$")


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


class Registry:
    def __init__(self) -> None:
        self.ids: Dict[str, List[Any]] = defaultdict(list)
        self.values: Dict[str, Dict[str, List[Any]]] = defaultdict(lambda: defaultdict(list))
        self.endpoints: Dict[str, set] = defaultdict(set)  # template -> metody

    def observe(self, url: str, method: str, status: int, body: Any) -> None:
        path = urlsplit(url).path
        tpl = normalize_path(path)
        self.endpoints[tpl].add(method)
        if not (200 <= status < 300) or body is None:
            return
        res = resource_info(tpl)["resource"]
        if not res:
            return
        key = normalize_name(res)
        ents, _ = unwrap_entities(body)
        for e in ents[:50]:
            if isinstance(e, dict):
                for k, v in e.items():
                    if not isinstance(v, (dict, list)) and v not in self.values[key][k][-5:]:
                        self.values[key][k].append(v)
                if "id" in e and isinstance(e["id"], (int, str)) and e["id"] not in self.ids[key]:
                    self.ids[key].append(e["id"])

    def ids_for(self, name: str) -> List[Any]:
        return self.ids.get(normalize_name(name), [])

    def fk_value(self, field_name: str, n: int = 0) -> Optional[Any]:
        m = FK_RE.match(field_name)
        if not m:
            return None
        ids = self.ids_for(m.group(1))
        return ids[n % len(ids)] if ids else None


def parse_validation_errors(status: int, body: Any) -> Dict[str, Dict[str, Any]]:
    """Różne formaty błędów (FastAPI, Express-validator, DRF, Spring, Zod) -> {pole: {msg, allowed}}."""
    out: Dict[str, Dict[str, Any]] = {}
    if status not in (400, 409, 422) or not isinstance(body, (dict, list)):
        return out

    def add(field: Any, msg: Any) -> None:
        if isinstance(field, list):
            field = next((f for f in reversed(field) if isinstance(f, str)), "")
        field, msg = str(field or ""), str(msg or "")
        if not field:
            return
        allowed = []
        if re.search(r"one of|should be|must be|allowed|enum", msg, re.I):
            allowed = re.findall(r"['\"]([^'\"]{1,40})['\"]", msg)
        out[field] = {"msg": msg[:160], "allowed": allowed}

    items: List[Any] = []
    if isinstance(body, dict):
        for k in ("detail", "errors", "issues", "violations"):
            v = body.get(k)
            if isinstance(v, list):
                items += v
        if not items:
            for k, v in body.items():  # DRF: {field: [msgs]}
                if isinstance(v, list) and v and isinstance(v[0], str):
                    add(k, v[0])
    else:
        items = body
    for it in items:
        if isinstance(it, dict):
            add(it.get("loc") or it.get("field") or it.get("param") or it.get("path") or it.get("name"),
                it.get("msg") or it.get("message") or it.get("defaultMessage"))
    return out


NAME_RULES = [
    (("password", "passwd", "pwd", "pass"), "{pwd}"),
    (("email", "mail"), "email"),
    (("phone", "tel", "mobile"), "+48500100200"),
    (("url", "website", "link"), "https://example.test/p{n}"),
    (("ip", "ipv4", "addr", "address"), "10.20.{n}.15"),
    (("hostname", "host", "server", "node", "domain"), "srv-auto-{n:02d}.example.test"),
    (("mac",), "00:1A:2B:3C:4D:{n:02d}"),
    (("severity", "priority", "level", "criticality"), "high"),
    (("status", "state"), "open"),
    (("env", "environment"), "production"),
    (("search", "query", "q"), "apple"),
    (("author", "user", "assignee", "owner", "login", "username"), "AuditAgent_{n}"),
    (("title", "name", "subject", "summary"), "Automated Probe {n}"),
    (("comment", "content", "message", "description", "body", "feedback", "text", "note"), "Automated probe content #{n}"),
]


class FieldInferer:
    def __init__(self, cfg, registry: Registry):
        self.cfg, self.reg = cfg, registry
        self.n = 0
        self.learned: Dict[str, Any] = {}
        self.pwd = cfg.auth_pass or "Apim1ner!Pass42"

    def learn(self, errors: Dict[str, Dict[str, Any]]) -> None:
        for f, info in errors.items():
            if info["allowed"]:
                self.learned[norm(f)] = info["allowed"][0]
            else:
                self.learned.setdefault(norm(f), None)

    def value_for(self, meta: Dict[str, Any], mode: str = "happy") -> Any:
        self.n += 1
        n = self.n
        keys = [meta.get("formcontrol"), meta.get("name"), meta.get("id"), meta.get("label"), meta.get("aria"), meta.get("placeholder")]
        label = " ".join(k for k in keys if k)
        for k in keys:
            if k and norm(k) in self.learned and self.learned[norm(k)] is not None:
                return self.learned[norm(k)]
        typ, tag = meta.get("type", "text"), meta.get("tag", "input")
        if tag == "select":
            opts = [o for o in meta.get("options", []) if o[0] not in ("", None)]
            if not opts:
                return None
            for k in keys:
                fk = self.reg.fk_value(k or "", n)
                if fk is not None:
                    for v, _t in opts:
                        if str(v) == str(fk):
                            return v
            return opts[n % len(opts)][0]
        for k in keys:
            fk = self.reg.fk_value(k or "", n)
            if fk is not None:
                return str(fk)
        if typ == "password":
            return self.pwd
        if typ == "email":
            return f"probe{n}@example.test"
        if typ in ("number", "range"):
            lo = float(meta["min"]) if meta.get("min") not in ("", None) else 1
            return str(int(max(lo, 1)))
        if typ == "date":
            return date.today().isoformat()
        if typ == "datetime-local":
            return datetime.now().strftime("%Y-%m-%dT%H:%M")
        if typ == "time":
            return "12:00"
        if typ == "url":
            return f"https://example.test/p{n}"
        if typ == "tel":
            return "+48500100200"
        if typ == "color":
            return "#336699"
        low = norm(label)
        val: Optional[str] = None
        for words, tpl in NAME_RULES:
            if any(norm(w) == low or (len(w) > 2 and norm(w) in low) for w in words):
                val = tpl
                break
        if val == "email":
            val = f"probe{n}@example.test"
        val = (val or "AutoProbe_{n}").format(n=n, pwd=self.pwd)
        ml = meta.get("maxlength") or 0
        if ml and ml > 0 and ml != 524288:
            val = val[:ml]
        mn = meta.get("minlength") or 0
        if mn and mn > 0 and mn != -1 and len(val) < mn:
            val = (val + "x" * mn)[:max(mn, len(val))]
        return val
