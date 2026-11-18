"""Agent eksploracyjny: autonomiczny crawler SPA + heurystyki CRUD, generujący ruch dla sniffera eBPF."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from playwright.sync_api import sync_playwright  # noqa: E402

from auth import AuthState, api_headers, authenticate, install_token  # noqa: E402
from config import Config  # noqa: E402
from crud import CrudProber  # noqa: E402
from fields import FieldInferer, Registry, norm, parse_validation_errors  # noqa: E402
from common.logs import get_logger  # noqa: E402
from common.traffic import normalize_path  # noqa: E402

log = get_logger("explorer")

ROUTE_HOOK_JS = """(() => { if (window.__apmHooked) return; window.__apmHooked = true; window.__apmRoutes = new Set();
const rec = () => { try { window.__apmRoutes.add(location.pathname + location.search + location.hash); } catch(e){} };
for (const fn of ['pushState','replaceState']) { const o = history[fn]; history[fn] = function(){ const r = o.apply(this, arguments); rec(); return r; }; }
window.addEventListener('hashchange', rec); window.addEventListener('popstate', rec); rec(); })();"""

LINKS_JS = """() => { const out = []; document.querySelectorAll('a[href],[routerlink],[ng-reflect-router-link],[data-href],[to]').forEach(e => {
 for (const a of ['href','routerlink','ng-reflect-router-link','data-href','to']) { const v = e.getAttribute(a); if (v) { out.push([a, v]); break; } } });
 return {links: out, routes: Array.from(window.__apmRoutes || [])}; }"""

FIELDS_JS = """(root) => Array.from(root.querySelectorAll('input,select,textarea')).filter(e => !['hidden','submit','button','image','reset','file'].includes((e.type||'').toLowerCase()))
 .map((e,i) => { e.setAttribute('data-apm-idx', i); return {idx:i, tag:e.tagName.toLowerCase(), type:(e.type||'text').toLowerCase(), name:e.name||'', id:e.id||'',
 placeholder:e.placeholder||'', aria:e.getAttribute('aria-label')||'', label:(e.labels&&e.labels[0]?e.labels[0].innerText:'')||'', formcontrol:e.getAttribute('formcontrolname')||'',
 required:!!e.required, minlength:e.minLength, maxlength:e.maxLength, min:e.min, max:e.max, disabled:!!e.disabled,
 visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length), options:e.tagName==='SELECT'?Array.from(e.options).map(o=>[o.value,o.text]):[]}; })"""

BTN_JS = """() => Array.from(document.querySelectorAll('button,[role=button],input[type=button]')).map(e => { const r = e.getBoundingClientRect();
 return {text:(e.innerText||e.value||'').trim().slice(0,60), aria:e.getAttribute('aria-label')||'', cls:(e.className&&e.className.toString?e.className.toString():'').slice(0,80),
 type:(e.type||'').toLowerCase(), disabled:!!e.disabled||e.getAttribute('aria-disabled')==='true', visible:!!(r.width||r.height), inForm:!!e.closest('form')}; })"""

DESTRUCTIVE = re.compile(r"(delete|remove|destroy|drop|purge|wipe|reset|logout|log out|sign out|usuń|kasuj|danger|wyloguj)", re.I)
POSITIVE = re.compile(r"(add|create|new|save|submit|send|apply|update|edit|confirm|dodaj|zapisz|wyślij|search|filter|more|next|show)", re.I)
JS_ENDPOINT_RE = re.compile(r"""["'`](/(?:api|rest|v\d+|graphql)[A-Za-z0-9_\-/{}.:$]*)["'`]""")


class Explorer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.reg = Registry()
        self.infer = FieldInferer(cfg, self.reg)
        self.t0 = time.time()
        self.stats: Counter = Counter()
        self.bodies: Dict[str, Any] = {}
        self.calls_fh = open(os.path.join(cfg.data_dir, "playwright_calls.jsonl"), "w", encoding="utf-8")
        self.visited: set = set()
        self.tpl_counts: Dict[str, int] = defaultdict(int)
        self.form_pages: List[str] = []
        self.js_hints: List[str] = []
        self.report: Dict[str, Any] = {"profiles": [], "validation_errors": {}, "pages": []}
        self.deadline = self.t0 + cfg.max_seconds

    # ---------------------------------------------------------------- logowanie żądań
    def record(self, rec: Dict[str, Any]) -> None:
        rec["t"] = round(time.time() - self.t0, 2)
        self.calls_fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self.calls_fh.flush()

    def on_response(self, resp) -> None:
        try:
            if not resp.url.startswith(self.cfg.origin):
                return
            req = resp.request
            ct = (resp.headers.get("content-type") or "").lower()
            if req.resource_type not in ("xhr", "fetch") and "json" not in ct:
                return
            body = None
            if "json" in ct:
                try:
                    body = resp.json()
                except Exception:  # noqa: BLE001
                    body = None
            self.reg.observe(resp.url, req.method, resp.status, body)
            post = None
            try:
                post = req.post_data
            except Exception:  # noqa: BLE001
                pass
            if post and req.method in ("POST", "PUT", "PATCH"):
                try:
                    self.bodies[f"{req.method} {normalize_path(urlsplit(resp.url).path)}"] = json.loads(post)
                except ValueError:
                    pass
            self.stats["api_calls"] += 1
            self.record({"source": "browser", "method": req.method, "url": resp.url, "status": resp.status, "rtype": req.resource_type, "req_body": (post or "")[:1500]})
        except Exception:  # noqa: BLE001
            pass

    # ---------------------------------------------------------------- pomocnicze
    def time_ok(self) -> bool:
        return time.time() < self.deadline

    def settle(self, page, ms: Optional[int] = None) -> None:
        try:
            page.wait_for_load_state("networkidle", timeout=ms or self.cfg.idle_wait_ms)
        except Exception:  # noqa: BLE001
            pass

    def dismiss_overlays(self, page) -> None:
        try:
            page.keyboard.press("Escape")
            btns = page.locator("[role='dialog'] button:visible, .cdk-overlay-container button:visible, [aria-label*='dismiss' i]:visible, [aria-label*='close' i]:visible, button:has-text('Accept'):visible, button:has-text('Got it'):visible")
            for i in range(min(btns.count(), 3)):
                btns.nth(i).click(timeout=800)
                time.sleep(0.2)
        except Exception:  # noqa: BLE001
            pass

    def url_key(self, url: str) -> str:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}{normalize_path(p.path)}#{normalize_path(p.fragment) if p.fragment.startswith('/') else p.fragment}"

    def resolve(self, page_url: str, attr: str, value: str) -> Optional[str]:
        if not value or value.startswith(("mailto:", "tel:", "javascript:", "blob:", "data:")) or value == "#":
            return None
        if value.startswith(("#/", "#!/")):
            return f"{self.cfg.origin}/{value}"
        if attr != "href" and value.startswith("/") and "#/" in page_url:
            return f"{self.cfg.origin}/#{value}"
        full = urljoin(page_url, value)
        return full if urlsplit(full).netloc == urlsplit(self.cfg.origin).netloc else None

    def harvest(self, page, queue: List[str]) -> None:
        try:
            data = page.evaluate(LINKS_JS)
        except Exception:  # noqa: BLE001
            return
        cand = [self.resolve(page.url, a, v) for a, v in data["links"]]
        cand += [urljoin(self.cfg.origin + "/", r.lstrip("/")) if not r.startswith("#") else f"{self.cfg.origin}/{r}" for r in data["routes"]]
        for u in cand:
            if not u:
                continue
            key = self.url_key(u)
            tpl = key.split("#")[0]
            if key not in self.visited and u not in queue and self.tpl_counts[tpl] < 3:
                queue.append(u)

    # ---------------------------------------------------------------- formularze
    def fill_forms(self, page, url: str) -> None:
        roots = page.locator("form")
        n = min(roots.count(), 6)
        targets = [roots.nth(i) for i in range(n)] or [page.locator("body")]
        for root in targets:
            if not self.time_ok():
                return
            try:
                self.process_form(page, root, url)
            except Exception as e:  # noqa: BLE001
                log.debug("form error: %s", e)

    def apply(self, root, f: Dict[str, Any], value: Any) -> None:
        loc = root.locator(f'[data-apm-idx="{f["idx"]}"]')
        if f["type"] == "checkbox":
            loc.check(timeout=1000)
        elif f["type"] == "radio":
            loc.check(timeout=1000)
        elif f["tag"] == "select":
            if value is not None:
                loc.select_option(value=value, timeout=1500)
        elif value is not None:
            loc.fill(str(value), timeout=1500)

    def submit_form(self, page, root, fields: List[Dict[str, Any]], mode: str) -> Optional[Dict[str, Any]]:
        required = [f for f in fields if f["required"] and f["type"] not in ("checkbox", "radio")] or [f for f in fields if f["tag"] != "select"][:1]
        for f in fields:
            try:
                v = self.infer.value_for(f, mode)
                if mode == "long" and f is (fields[0]) and f["type"] in ("text", "textarea", "search"):
                    v = "A" * 400
                if mode == "empty" and required and f is required[0]:
                    v = ""
                self.apply(root, f, v)
            except Exception:  # noqa: BLE001
                pass
        for i in range(min(root.locator("mat-select:visible").count(), 3)):
            try:
                root.locator("mat-select:visible").nth(i).click(timeout=1200)
                page.locator("mat-option").first.click(timeout=1200)
            except Exception:  # noqa: BLE001
                pass
        btn = root.locator("button[type='submit']:visible, input[type='submit']:visible").first
        if not btn.count():
            btn = root.locator("button:visible", has_text=POSITIVE).first
        result: Dict[str, Any] = {}
        try:
            with page.expect_response(lambda r: r.request.method in ("POST", "PUT", "PATCH") and r.url.startswith(self.cfg.origin), timeout=2500) as info:
                if btn.count():
                    btn.click(timeout=2000)
                else:
                    page.keyboard.press("Enter")
            r = info.value
            try:
                body = r.json()
            except Exception:  # noqa: BLE001
                body = None
            result = {"status": r.status, "body": body, "url": r.url}
        except Exception:  # noqa: BLE001
            return None
        self.settle(page, 1500)
        self.stats["forms_submitted"] += 1
        return result

    def process_form(self, page, root, url: str) -> None:
        fields = [f for f in root.evaluate(FIELDS_JS) if f["visible"] and not f["disabled"]]
        if not fields:
            return
        sig = self.url_key(url) + "|" + ",".join(sorted(norm(f["name"] or f["formcontrol"] or f["id"]) for f in fields))
        if sig in self.visited:
            return
        self.visited.add(sig)
        if url not in self.form_pages:
            self.form_pages.append(url)
        modes = ["happy"] + (["empty", "long"] if self.cfg.negative_probes else [])
        for mi, mode in enumerate(modes):
            if mi:
                page.goto(url, wait_until="domcontentloaded", timeout=self.cfg.nav_timeout_ms)
                self.settle(page)
                self.dismiss_overlays(page)
                roots = page.locator("form")
                root = roots.first if roots.count() else page.locator("body")
                fields = [f for f in root.evaluate(FIELDS_JS) if f["visible"] and not f["disabled"]]
                if not fields:
                    return
            res = self.submit_form(page, root, fields, mode)
            for attempt in range(2):
                if res and mode == "happy" and res["status"] >= 400:
                    errs = parse_validation_errors(res["status"], res["body"])
                    if not errs:
                        break
                    self.infer.learn(errs)
                    self.report["validation_errors"].update({k: v["msg"] for k, v in errs.items()})
                    self.stats["validation_retries"] += 1
                    res = self.submit_form(page, root, fields, mode)
                else:
                    break

    # ---------------------------------------------------------------- przyciski / nawigacja
    def click_buttons(self, page, url: str, queue: List[str]) -> None:
        try:
            items = page.evaluate(BTN_JS)
        except Exception:  # noqa: BLE001
            return
        cands = []
        for b in items:
            label = f"{b['text']} {b['aria']} {b['cls']}"
            if not b["visible"] or b["disabled"] or not b["text"] or (b["inForm"] and b["type"] == "submit"):
                continue
            if self.cfg.safe_mode and DESTRUCTIVE.search(label):
                continue
            cands.append((0 if POSITIVE.search(label) else 1, b["text"]))
        seen = set()
        for _, text in sorted(cands)[: self.cfg.max_buttons]:
            if text in seen or not self.time_ok():
                continue
            seen.add(text)
            try:
                page.locator("button, [role=button]", has_text=text).first.click(timeout=1200)
                time.sleep(0.35)
                self.dismiss_overlays(page)
                self.stats["buttons_clicked"] += 1
                if self.url_key(page.url) != self.url_key(url):
                    self.harvest(page, queue)
                    page.goto(url, wait_until="domcontentloaded", timeout=self.cfg.nav_timeout_ms)
                    self.settle(page, 1500)
            except Exception:  # noqa: BLE001
                pass

    def click_nav(self, page, url: str, queue: List[str]) -> None:
        sel = "[role=tab]:visible, [role=menuitem]:visible, mat-tab-header .mat-mdc-tab:visible, nav button:visible"
        loc = page.locator(sel)
        for i in range(min(loc.count(), 8)):
            if not self.time_ok():
                return
            try:
                loc.nth(i).click(timeout=1000)
                time.sleep(0.3)
                self.harvest(page, queue)
            except Exception:  # noqa: BLE001
                pass
        for sel2 in ("table tbody tr:visible", "[role=row]:visible", "mat-card:visible"):
            try:
                rows = page.locator(sel2)
                for i in range(min(rows.count(), 2)):
                    rows.nth(i).click(timeout=1000)
                    time.sleep(0.4)
                    if self.url_key(page.url) != self.url_key(url):
                        self.harvest(page, queue)
                        page.goto(url, wait_until="domcontentloaded", timeout=self.cfg.nav_timeout_ms)
                        self.settle(page, 1500)
                        rows = page.locator(sel2)
            except Exception:  # noqa: BLE001
                pass

    def scroll_paginate(self, page) -> None:
        try:
            for _ in range(3):
                page.mouse.wheel(0, 2500)
                time.sleep(0.3)
            nxt = page.locator("[aria-label*='next' i]:visible, button:has-text('Next'):visible, [rel=next]:visible").first
            for _ in range(2):
                if nxt.count() and nxt.is_enabled():
                    nxt.click(timeout=1000)
                    time.sleep(0.4)
        except Exception:  # noqa: BLE001
            pass

    # ---------------------------------------------------------------- strona
    def visit(self, page, url: str, queue: List[str], forms: bool = True) -> None:
        page.goto(url, wait_until="domcontentloaded", timeout=self.cfg.nav_timeout_ms)
        self.settle(page)
        time.sleep(0.4)
        self.dismiss_overlays(page)
        self.harvest(page, queue)
        if forms:
            self.fill_forms(page, url)
            self.click_buttons(page, url, queue)
            self.click_nav(page, url, queue)
            self.scroll_paginate(page)
        self.harvest(page, queue)
        self.stats["pages"] += 1
        self.report["pages"].append(url)

    def crawl(self, ctx, auth: AuthState, deadline: float) -> None:
        page = ctx.new_page()
        queue = [self.cfg.target_url] + [self.cfg.origin + p if p.startswith(("/", "#")) else p for p in self.cfg.seed_paths]
        queue = list(dict.fromkeys(queue))
        pages = 0
        while queue and pages < self.cfg.max_pages and time.time() < deadline:
            url = queue.pop(0)
            key = self.url_key(url)
            if key in self.visited:
                continue
            self.visited.add(key)
            self.tpl_counts[key.split("#")[0]] += 1
            pages += 1
            log.info("[%s %d/%d] %s", auth.name, pages, self.cfg.max_pages, url)
            try:
                self.visit(page, url, queue)
            except Exception as e:  # noqa: BLE001
                log.warning("Ostrzeżenie przy %s: %s", url, str(e)[:120])
        if self.cfg.second_pass and self.form_pages and time.time() < deadline:
            log.info("Druga runda formularzy (rejestr FK uzupełniony: %s)", {k: len(v) for k, v in self.reg.ids.items()})
            for url in self.form_pages[:5]:
                self.visited.discard("2nd|" + url)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=self.cfg.nav_timeout_ms)
                    self.settle(page)
                    for root_i in range(min(page.locator("form").count(), 3)):
                        root = page.locator("form").nth(root_i)
                        fields = [f for f in root.evaluate(FIELDS_JS) if f["visible"] and not f["disabled"]]
                        if fields:
                            self.submit_form(page, root, fields, "happy")
                except Exception:  # noqa: BLE001
                    pass
        page.close()

    # ---------------------------------------------------------------- JS / spec
    def harvest_js(self, ctx, page_url: str) -> None:
        try:
            page = ctx.new_page()
            page.goto(page_url, wait_until="domcontentloaded", timeout=self.cfg.nav_timeout_ms)
            srcs = page.evaluate("() => Array.from(document.scripts).map(s => s.src).filter(Boolean)")
            page.close()
            found = set()
            for s in srcs[:12]:
                if not s.startswith(self.cfg.origin):
                    continue
                r = ctx.request.get(s, timeout=8000)
                if r.status == 200:
                    for m in JS_ENDPOINT_RE.findall(r.text()[:6_000_000]):
                        found.add(re.sub(r"\$\{[^}]*\}", "{id}", m))
            self.js_hints = sorted(found)[:200]
            log.info("Z bundli JS wyciągnięto %d kandydatów na endpointy", len(self.js_hints))
        except Exception as e:  # noqa: BLE001
            log.debug("harvest_js: %s", e)

    def probe_spec(self, ctx) -> None:
        for p in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json"):
            try:
                r = ctx.request.get(self.cfg.origin + p, timeout=4000)
                if r.status == 200 and "json" in (r.headers.get("content-type") or ""):
                    with open(os.path.join(self.cfg.data_dir, "ground_truth_spec.json"), "w", encoding="utf-8") as f:
                        json.dump(r.json(), f)
                    log.info("Zapisano ground truth spec z %s (tylko do ewaluacji)", p)
                    return
            except Exception:  # noqa: BLE001
                continue

    # ---------------------------------------------------------------- całość
    def wait_ready(self) -> None:
        start = time.time()
        while time.time() - start < 90:
            try:
                with urllib.request.urlopen(self.cfg.target_url, timeout=3) as r:
                    if r.status < 500:
                        break
            except Exception:  # noqa: BLE001
                time.sleep(1.5)
        flag = os.path.join(self.cfg.data_dir, "sniffer_ready.flag")
        start = time.time()
        while not os.path.exists(flag) and time.time() - start < self.cfg.sniffer_wait_s:
            time.sleep(0.5)
        if not os.path.exists(flag):
            log.warning("Sniffer eBPF nie zgłosił gotowości w %ds – ruch może nie zostać przechwycony!", self.cfg.sniffer_wait_s)
        time.sleep(1.5)

    def run(self) -> None:
        self.wait_ready()
        profiles = self.cfg.profiles
        per_profile = self.cfg.max_seconds / max(1, len(profiles))
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.cfg.headless, args=["--no-sandbox"])
            for idx, prof in enumerate(profiles):
                deadline = time.time() + per_profile
                har = os.path.join(self.cfg.data_dir, f"explorer_{prof.get('name', idx)}.har")
                kw: Dict[str, Any] = {"viewport": {"width": 1440, "height": 900}, "ignore_https_errors": True, "record_har_path": har, "record_har_content": "omit"}
                if self.cfg.force_identity:
                    kw["extra_http_headers"] = {"Accept-Encoding": "identity"}
                ctx = browser.new_context(**kw)
                ctx.add_init_script(script=ROUTE_HOOK_JS)
                ctx.on("response", self.on_response)
                log.info("=== Profil: %s ===", prof.get("name"))
                auth = AuthState(name=prof.get("name", "anonymous"))
                if prof.get("name") != "anonymous":
                    page = ctx.new_page()
                    auth = authenticate(ctx, page, self.cfg, prof, log)
                    page.close()
                    install_token(ctx, auth, self.cfg)
                self.visited = set()  # reset stanu per profil
                self.tpl_counts.clear()
                if idx == 0 and self.cfg.harvest_js:
                    self.harvest_js(ctx, self.cfg.target_url)
                if idx == 0 and self.cfg.probe_spec:
                    self.probe_spec(ctx)
                self.crawl(ctx, auth, deadline)
                if self.cfg.crud_probe and (auth.name != "anonymous" or len(profiles) == 1):
                    n = CrudProber(self.cfg, ctx, self.reg, self.bodies, api_headers(auth, self.cfg), self.record, log).run(self.js_hints)
                    log.info("CRUD prober: %d wywołań", n)
                try:
                    ctx.storage_state(path=os.path.join(self.cfg.data_dir, f"auth_state_{auth.name}.json"))
                except Exception:  # noqa: BLE001
                    pass
                self.report["profiles"].append({"name": auth.name, "auth_method": auth.method or "none", "token": bool(auth.token), "notes": auth.notes})
                ctx.close()
            browser.close()
        self.finish()

    def finish(self) -> None:
        self.calls_fh.close()
        self.report.update(stats=dict(self.stats), seconds=round(time.time() - self.t0, 1),
                           endpoints_seen={k: sorted(v) for k, v in self.reg.endpoints.items()},
                           resource_ids={k: len(v) for k, v in self.reg.ids.items()})
        with open(os.path.join(self.cfg.data_dir, "explorer_report.json"), "w", encoding="utf-8") as f:
            json.dump(self.report, f, ensure_ascii=False, indent=2, default=str)
        with open(os.path.join(self.cfg.data_dir, "static_api_hints.json"), "w", encoding="utf-8") as f:
            json.dump(self.js_hints, f)
        with open(os.path.join(self.cfg.data_dir, "explorer_done.flag"), "w", encoding="utf-8") as f:
            f.write("done\n")
        log.info("Zakończono: %s (%.0fs)", dict(self.stats), time.time() - self.t0)


def main() -> None:
    cfg = Config.from_env()
    os.makedirs(cfg.data_dir, exist_ok=True)
    try:
        Explorer(cfg).run()
    except Exception:
        log.exception("Explorer zakończył się błędem – zapisuję flagę, by pipeline nie zawisł")
        with open(os.path.join(cfg.data_dir, "explorer_done.flag"), "w", encoding="utf-8") as f:
            f.write("failed\n")
        raise


if __name__ == "__main__":
    main()
