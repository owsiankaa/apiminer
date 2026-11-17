import os
import re
import time
import urllib.request
from collections import deque
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

TARGET_URL = os.getenv("TARGET_URL", "http://target_app:3000")
MAX_PAGES = int(os.getenv("MAX_PAGES", "10"))


def wait_for_target_ready(url: str, timeout: int = 45):
    """Czeka aż serwer docelowy (np. emulowany amd64 na ARM64) zacznie odpowiadać."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    return
        except Exception:
            time.sleep(1.5)


def dismiss_overlays(page):
    """Generycznie zamyka modale powitalne, banery cookies i nakładki blokujące DOM."""
    try:
        page.keyboard.press("Escape")
        time.sleep(0.3)
        overlay_btns = page.locator(
            "[role='dialog'] button, .cdk-overlay-container button, [aria-label*='dismiss' i], [aria-label*='close' i]"
        )
        for i in range(min(overlay_btns.count(), 4)):
            btn = overlay_btns.nth(i)
            if btn.is_visible():
                btn.click(timeout=1000)
                time.sleep(0.3)
    except Exception:
        pass


def infer_input_value(attrs: dict, counter: int) -> str:
    meta = " ".join(str(v) for v in attrs.values() if v).lower()
    input_type = (attrs.get("type") or "text").lower()

    if input_type == "password" or "pass" in meta:
        return "TestPass123!"
    if input_type == "number" or any(k in meta for k in ["_id", "id", "count", "qty", "port", "age", "amount", "price", "rating"]):
        return "1"
    if input_type == "email" or "mail" in meta:
        return f"probe{counter}@juice-sh.op"
    if input_type == "date" or "date" in meta:
        return "2026-11-17"
    if any(k in meta for k in ["ip", "addr", "ipv4"]):
        return f"10.20.{counter}.15"
    if any(k in meta for k in ["host", "server", "node", "domain"]):
        return f"srv-auto-node-0{counter}"
    if any(k in meta for k in ["search", "query", "q"]):
        return "apple"
    if any(k in meta for k in ["author", "user", "assignee", "owner", "login"]):
        return f"AuditAgent_{counter}"
    if any(k in meta for k in ["title", "name", "subject", "summary", "comment", "feedback"]):
        return f"Automated Security Probe #{counter}"
    return f"AutoProbePayload_{counter}"


def fill_all_forms(page, seed: int):
    inputs = page.locator("input:not([type='hidden']):not([type='submit']):not([type='button']), textarea")
    input_count = inputs.count()
    print(f"[Explorer] Wykryto {input_count} pól wejściowych na bieżącym widoku.")

    for i in range(input_count):
        field = inputs.nth(i)
        try:
            if not field.is_visible() or not field.is_enabled():
                continue
            attrs = {
                "type": field.get_attribute("type"),
                "name": field.get_attribute("name"),
                "id": field.get_attribute("id"),
                "placeholder": field.get_attribute("placeholder"),
                "aria-label": field.get_attribute("aria-label"),
            }
            val = infer_input_value(attrs, seed + i)
            field.fill(val, timeout=1500)
            if "search" in " ".join(str(v) for v in attrs.values() if v).lower():
                field.press("Enter")
                time.sleep(0.5)
        except Exception:
            pass

    selects = page.locator("select")
    for s_idx in range(selects.count()):
        sel = selects.nth(s_idx)
        try:
            if sel.is_visible() and sel.locator("option").count() > 1:
                sel.select_option(index=1, timeout=1500)
        except Exception:
            pass

    submit_btns = page.locator("button[type='submit'], input[type='submit']")
    for b_idx in range(submit_btns.count()):
        btn = submit_btns.nth(b_idx)
        try:
            if btn.is_visible() and btn.is_enabled():
                btn.click(timeout=2000)
                page.wait_for_load_state("networkidle", timeout=3000)
                time.sleep(0.5)
        except Exception:
            pass


def trigger_state_mutations(page):
    destructive_pattern = re.compile(r"(delete|remove|destroy|drop|usuń|kasuj|danger)", re.I)
    buttons = page.locator("button:not([type='submit'])")
    total = min(buttons.count(), 12)

    for i in range(total):
        btn = buttons.nth(i)
        try:
            if not btn.is_visible() or not btn.is_enabled():
                continue
            label = (
                (btn.inner_text() or "")
                + " "
                + (btn.get_attribute("class") or "")
                + " "
                + (btn.get_attribute("aria-label") or "")
            )
            if destructive_pattern.search(label):
                continue
            btn.click(timeout=1200)
            time.sleep(0.4)
            dismiss_overlays(page)
        except Exception:
            pass


def discover_links(page, base_origin: str) -> list[str]:
    found = []
    anchors = page.locator("a[href], [routerlink]")
    for i in range(anchors.count()):
        href = anchors.nth(i).get_attribute("href") or anchors.nth(i).get_attribute("routerlink")
        if not href or href.startswith(("mailto:", "tel:", "javascript:")):
            continue
        if href.startswith("#/"):
            full_url = f"{base_origin}/{href}"
        else:
            full_url = urljoin(page.url, href)
        parsed = urlparse(full_url)
        if f"{parsed.scheme}://{parsed.netloc}" == base_origin:
            found.append(full_url)
    return list(dict.fromkeys(found))


def run_exploration():
    print(f"[Explorer] Oczekuję na gotowość aplikacji docelowej: {TARGET_URL}")
    wait_for_target_ready(TARGET_URL)
    time.sleep(3)

    base_parsed = urlparse(TARGET_URL)
    base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    seed_urls = [
        TARGET_URL,
        f"{base_origin}/#/login",
        f"{base_origin}/#/register",
        f"{base_origin}/#/contact",
        f"{base_origin}/#/score-board",
    ]
    visited = set()
    queue = deque(seed_urls)
    page_counter = 0

    print(f"[Explorer] Start autonomicznej eksploracji SPA: {TARGET_URL}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            extra_http_headers={"Accept-Encoding": "identity"},
        )
        page = context.new_page()

        while queue and page_counter < MAX_PAGES:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            page_counter += 1

            print(f"[Explorer] [{page_counter}/{MAX_PAGES}] Analiza widoku: {url}")
            try:
                page.goto(url, wait_until="networkidle", timeout=10000)
                time.sleep(0.8)
                dismiss_overlays(page)
            except Exception as e:
                print(f"[Explorer] Ostrzeżenie przy ładowaniu {url}: {e}")
                continue

            for link in discover_links(page, base_origin):
                if link not in visited:
                    queue.append(link)

            fill_all_forms(page, seed=page_counter * 10)
            trigger_state_mutations(page)

        browser.close()

    with open("/data/explorer_done.flag", "w", encoding="utf-8") as f:
        f.write("done\n")
    print(f"[Explorer] Zakończono eksplorację ({len(visited)} odwiedzonych widoków).")


if __name__ == "__main__":
    run_exploration()
