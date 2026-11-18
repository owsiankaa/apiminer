"""Uwierzytelnianie: token statyczny, login API, formularz UI (z auto-rejestracją), wstrzykiwanie JWT do SPA i żądań XHR/fetch."""
from __future__ import annotations

import json
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
TOKEN_KEYS = {"token", "access_token", "accesstoken", "jwt", "id_token", "idtoken", "authtoken", "bearer"}
LOGIN_PATHS = ["/#/login", "/login", "/signin", "/auth/login", "/#/signin", "/sign-in"]
REGISTER_PATHS = ["/#/register", "/register", "/signup", "/#/signup", "/sign-up"]
SUBMIT_RE = re.compile(r"(log ?in|sign ?in|zaloguj|register|sign ?up|create|submit|zarejestruj|continue)", re.I)


@dataclass
class AuthState:
    name: str = "anonymous"
    token: Optional[str] = None
    username: str = ""
    password: str = ""
    method: str = ""
    notes: List[str] = field(default_factory=list)


def find_token(obj: Any, depth: int = 0) -> Optional[str]:
    if depth > 5:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in TOKEN_KEYS and isinstance(v, str) and len(v) > 16:
                return v
        for v in obj.values():
            r = find_token(v, depth + 1)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj[:5]:
            r = find_token(v, depth + 1)
            if r:
                return r
    elif isinstance(obj, str):
        m = JWT_RE.search(obj)
        return m.group(0) if m else None
    return None


def random_creds() -> Dict[str, str]:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return {"username": f"apiminer_{suffix}@example.test", "password": "Apim1ner!Pass42"}


def install_token(ctx, auth: AuthState, cfg) -> None:
    """Token trafia do localStorage/cookie (dla SPA) oraz do nagłówka żądań XHR/fetch bez Authorization."""
    if not auth.token:
        return
    script = (
        "(()=>{try{const t=%s;for(const k of %s){localStorage.setItem(k,t);}"
        "document.cookie='token='+t+'; path=/';}catch(e){}})();" % (json.dumps(auth.token), json.dumps(cfg.auth_storage_keys))
    )
    ctx.add_init_script(script=script)
    header, value = cfg.auth_header.lower(), f"{cfg.auth_scheme} {auth.token}".strip()

    def handler(route):
        req = route.request
        try:
            if req.resource_type in ("xhr", "fetch") and header not in req.headers and req.url.startswith(cfg.origin):
                route.continue_(headers={**req.headers, header: value})
            else:
                route.continue_()
        except Exception:  # noqa: BLE001
            try:
                route.continue_()
            except Exception:  # noqa: BLE001
                pass

    ctx.route("**/*", handler)


def api_headers(auth: AuthState, cfg) -> Dict[str, str]:
    return {cfg.auth_header: f"{cfg.auth_scheme} {auth.token}".strip()} if auth.token else {}


def watch_login_responses(ctx, auth: AuthState) -> None:
    """Podsłuchuje odpowiedzi logowania i wyciąga z nich JWT (nawet jeśli SPA trzyma go tylko w pamięci)."""
    def on_resp(resp):
        try:
            if resp.request.method != "POST" or resp.status >= 400:
                return
            if not re.search(r"login|auth|token|session|signin", resp.url, re.I):
                return
            tok = find_token(resp.json())
            if tok:
                auth.token = tok
                auth.notes.append(f"token z {resp.url}")
        except Exception:  # noqa: BLE001
            pass

    ctx.on("response", on_resp)


def try_api_login(ctx, cfg, auth: AuthState) -> bool:
    if not cfg.auth_login_api or not auth.username:
        return False
    body_tpl = cfg.auth_login_body or '{"email":"{user}","password":"{pass}"}'
    try:
        body = json.loads(body_tpl.replace("{user}", auth.username).replace("{pass}", auth.password))
        r = ctx.request.post(cfg.origin + cfg.auth_login_api, data=body, timeout=8000)
        if r.status < 400:
            tok = find_token(r.json())
            if tok:
                auth.token, auth.method = tok, "api-login"
                return True
    except Exception as e:  # noqa: BLE001
        auth.notes.append(f"api-login: {type(e).__name__}")
    return False


def _settle(page, ms: int = 2500) -> None:
    try:
        page.wait_for_load_state("networkidle", timeout=ms)
    except Exception:  # noqa: BLE001
        pass


def _goto_first(page, cfg, candidates: List[str], need_password: bool = True) -> bool:
    for path in ([cfg.auth_login_url] if cfg.auth_login_url else []) + candidates:
        try:
            page.goto(cfg.origin + path if path.startswith(("/", "#")) else path, wait_until="domcontentloaded", timeout=cfg.nav_timeout_ms)
            _settle(page)
            if page.locator("input[type='password']:visible").count() > 0:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _fill_credentials(page, user: str, pwd: str, extra_text: str = "Apiminer") -> None:
    for i in range(page.locator("input[type='password']:visible").count()):
        page.locator("input[type='password']:visible").nth(i).fill(pwd, timeout=2000)
    sel = "input[type='email']:visible, input[name*='user' i]:visible, input[name*='mail' i]:visible, input[name*='login' i]:visible, input[id*='email' i]:visible, input[id*='user' i]:visible, input[type='text']:visible"
    first = page.locator(sel).first
    if first.count():
        first.fill(user, timeout=2000)
    # mat-select (Angular Material) – np. pytanie zabezpieczające
    for i in range(page.locator("mat-select:visible").count()):
        try:
            page.locator("mat-select:visible").nth(i).click(timeout=1500)
            page.locator("mat-option").first.click(timeout=1500)
        except Exception:  # noqa: BLE001
            pass
    others = page.locator("input[type='text']:visible, input:not([type]):visible")
    for i in range(1, others.count()):
        try:
            if not others.nth(i).input_value():
                others.nth(i).fill(extra_text, timeout=1000)
        except Exception:  # noqa: BLE001
            pass


def _submit(page) -> None:
    btn = page.locator("button[type='submit']:visible, input[type='submit']:visible").first
    if not btn.count():
        btn = page.locator("button:visible", has_text=SUBMIT_RE).first
    if btn.count():
        btn.click(timeout=3000)
    else:
        page.keyboard.press("Enter")
    time.sleep(0.8)
    _settle(page)


def try_ui_login(page, cfg, auth: AuthState) -> bool:
    if not auth.username or not _goto_first(page, cfg, LOGIN_PATHS):
        return False
    try:
        _fill_credentials(page, auth.username, auth.password)
        _submit(page)
    except Exception as e:  # noqa: BLE001
        auth.notes.append(f"ui-login: {type(e).__name__}")
        return False
    ok = auth.token is not None or page.locator("input[type='password']:visible").count() == 0
    if ok:
        auth.method = auth.method or "ui-login"
    return ok


def try_register(page, cfg, auth: AuthState) -> bool:
    if not _goto_first(page, cfg, REGISTER_PATHS):
        return False
    try:
        _fill_credentials(page, auth.username, auth.password)
        _submit(page)
        auth.notes.append("rejestracja wykonana")
        return True
    except Exception as e:  # noqa: BLE001
        auth.notes.append(f"register: {type(e).__name__}")
        return False


def authenticate(ctx, page, cfg, profile: Dict[str, Any], log) -> AuthState:
    auth = AuthState(name=profile.get("name", "user"), token=profile.get("token") or None,
                     username=profile.get("username", ""), password=profile.get("password", ""))
    watch_login_responses(ctx, auth)
    if auth.token:
        auth.method = "static-token"
        return auth
    if not auth.username and cfg.auto_register:
        auth.username, auth.password = random_creds().values()
        if try_register(page, cfg, auth):
            log.info("Zarejestrowano konto %s", auth.username)
    if try_api_login(ctx, cfg, auth) or try_ui_login(page, cfg, auth):
        log.info("Zalogowano (%s), token=%s", auth.method, "tak" if auth.token else "sesja/cookie")
    else:
        log.warning("Nie udało się zalogować profilu '%s' – eksploracja jako anonimowy. Notatki: %s", auth.name, auth.notes)
    return auth
