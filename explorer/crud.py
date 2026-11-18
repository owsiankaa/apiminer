"""Heurystyczne dopełnianie CRUD przez APIRequestContext (przechodzi przez tę samą sieć => widzi to eBPF)."""
from __future__ import annotations

import copy
import re
from typing import Any, Callable, Dict, List, Optional

from fields import Registry, norm  # noqa: F401
from common.ir import resource_info, unwrap_entities  # noqa: E402
from common.traffic import normalize_name  # noqa: E402


def fresh_body(body: Any, n: int, reg: Registry) -> Any:
    if not isinstance(body, dict):
        return body
    out = copy.deepcopy(body)
    for k, v in list(out.items()):
        if isinstance(v, str):
            out[k] = f"probe{n}@example.test" if "@" in v else f"{v[:60]} {n}"
        fk = reg.fk_value(k, n)
        if fk is not None:
            out[k] = fk
    return out


class CrudProber:
    def __init__(self, cfg, ctx, reg: Registry, bodies: Dict[str, Any], headers: Dict[str, str], record: Callable[[Dict[str, Any]], None], log):
        self.cfg, self.ctx, self.reg, self.bodies, self.headers, self.record, self.log = cfg, ctx, reg, bodies, headers, record, log
        self.calls = 0

    def call(self, method: str, path: str, body: Any = None) -> Optional[Dict[str, Any]]:
        if self.calls >= self.cfg.max_crud_calls:
            return None
        self.calls += 1
        try:
            r = self.ctx.request.fetch(self.cfg.origin + path, method=method, data=body, headers=self.headers, timeout=6000)
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                data = None
            self.reg.observe(self.cfg.origin + path, method, r.status, data)
            self.record({"source": "crud", "method": method, "url": path, "status": r.status, "req_body": body})
            return {"status": r.status, "data": data, "headers": r.headers}
        except Exception as e:  # noqa: BLE001
            self.log.debug("crud %s %s: %s", method, path, e)
            return None

    @staticmethod
    def item_url(coll: str, ident: Any) -> str:
        return coll.rstrip("/") + f"/{ident}" + ("/" if coll.endswith("/") else "")

    def run(self, hints: List[str]) -> int:
        templates = dict(self.reg.endpoints)
        collections = [t for t in templates if not t.rstrip("/").endswith("}") and "{" not in t][:25]
        self.log.info("CRUD: %d kolekcji do sprawdzenia", len(collections))
        for coll in collections:
            info = resource_info(coll)
            if not info["resource"] or info["rpc"]:
                continue
            ids = self.reg.ids_for(info["resource"])
            if "GET" in templates[coll] and ids:
                self.call("GET", self.item_url(coll, ids[0]))
            self.call("GET", self.item_url(coll, 999999))
            self.call("OPTIONS", coll)
            if "POST" in templates[coll] and ("POST " + coll) in self.bodies:
                base = self.bodies["POST " + coll]
                r = self.call("POST", coll, fresh_body(base, 1, self.reg))
                new_id = None
                if r and r["data"] is not None:
                    ents, _ = unwrap_entities(r["data"])
                    new_id = ents[0].get("id") if ents and isinstance(ents[0], dict) else None
                if new_id is not None:
                    url = self.item_url(coll, new_id)
                    self.call("GET", url)
                    for m in ("PATCH", "PUT"):
                        self.call(m, url, fresh_body(base, 2, self.reg))
                    self.call("POST", coll, fresh_body(base, 1, self.reg))  # duplikat
                    self.call("DELETE", url)       # tylko zasób stworzony przez nas
                    self.call("GET", url)          # oczekiwane 404
        for tpl in templates:  # zagnieżdżone: /parent/{x_id}/child
            m = re.match(r"^(.*)/\{(\w+)\}/([^/{}]+/?)$", tpl)
            if m and "GET" in templates[tpl]:
                ids = self.reg.ids_for(m.group(2).replace("_id", "")) or [1]
                self.call("GET", f"{m.group(1)}/{ids[0]}/{m.group(3)}")
        known = {t.rstrip("/") for t in templates}
        for h in hints[:20]:
            if "{" not in h and h.rstrip("/") not in known:
                self.call("GET", h)
        return self.calls
