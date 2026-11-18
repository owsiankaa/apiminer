from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List


def _b(name: str, default: bool) -> bool:
    return os.getenv(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


def _i(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass
class Config:
    target_url: str = "http://target_app:3000"
    data_dir: str = "/data"
    max_pages: int = 25
    max_seconds: int = 600
    max_buttons: int = 12
    max_crud_calls: int = 150
    nav_timeout_ms: int = 12000
    idle_wait_ms: int = 3000
    sniffer_wait_s: int = 60
    headless: bool = True
    safe_mode: bool = True          # nie klika "delete" i nie usuwa cudzych zasobów
    force_identity: bool = False    # True => Accept-Encoding: identity (parser i tak obsługuje gzip/deflate)
    negative_probes: bool = True    # puste / za długie pola -> ujawnia walidację
    crud_probe: bool = True
    harvest_js: bool = True
    probe_spec: bool = False        # zapisuje ewentualny swagger jako ground truth (NIE trafia do syntezy)
    second_pass: bool = True
    auto_register: bool = True
    auth_user: str = ""
    auth_pass: str = ""
    auth_token: str = ""
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    auth_login_url: str = ""
    auth_login_api: str = ""        # np. /rest/user/login
    auth_login_body: str = ""       # np. {"email":"{user}","password":"{pass}"}
    auth_storage_keys: List[str] = field(default_factory=lambda: ["token", "jwt", "access_token", "accessToken", "authToken", "id_token"])
    seed_paths: List[str] = field(default_factory=lambda: ["/", "/#/login", "/login", "/#/register", "/register", "/signup", "/#/contact", "/#/about", "/#/basket", "/dashboard", "/admin"])
    profiles: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def origin(self) -> str:
        from urllib.parse import urlsplit
        p = urlsplit(self.target_url)
        return f"{p.scheme}://{p.netloc}"

    @classmethod
    def from_env(cls) -> "Config":
        c = cls(
            target_url=os.getenv("TARGET_URL", "http://target_app:3000"),
            data_dir=os.getenv("DATA_DIR", "/data"),
            max_pages=_i("MAX_PAGES", 25), max_seconds=_i("MAX_SECONDS", 600), max_buttons=_i("MAX_BUTTONS", 12),
            max_crud_calls=_i("MAX_CRUD_CALLS", 150), nav_timeout_ms=_i("NAV_TIMEOUT_MS", 12000),
            sniffer_wait_s=_i("SNIFFER_READY_TIMEOUT", 60),
            headless=_b("HEADLESS", True), safe_mode=_b("SAFE_MODE", True), force_identity=_b("FORCE_IDENTITY", False),
            negative_probes=_b("NEGATIVE_PROBES", True), crud_probe=_b("CRUD_PROBE", True), harvest_js=_b("HARVEST_JS", True),
            probe_spec=_b("PROBE_SPEC", False), second_pass=_b("SECOND_PASS", True), auto_register=_b("AUTO_REGISTER", True),
            auth_user=os.getenv("AUTH_USER", ""), auth_pass=os.getenv("AUTH_PASS", ""), auth_token=os.getenv("AUTH_TOKEN", ""),
            auth_header=os.getenv("AUTH_HEADER", "Authorization"), auth_scheme=os.getenv("AUTH_SCHEME", "Bearer"),
            auth_login_url=os.getenv("AUTH_LOGIN_URL", ""), auth_login_api=os.getenv("AUTH_LOGIN_API", ""),
            auth_login_body=os.getenv("AUTH_LOGIN_BODY", ""),
        )
        if os.getenv("AUTH_STORAGE_KEYS"):
            c.auth_storage_keys = [k.strip() for k in os.getenv("AUTH_STORAGE_KEYS", "").split(",") if k.strip()]
        if os.getenv("SEED_PATHS"):
            c.seed_paths = [k.strip() for k in os.getenv("SEED_PATHS", "").split(",") if k.strip()]
        raw = os.getenv("PROFILES", "")
        if raw:
            try:
                c.profiles = json.loads(raw)
            except ValueError:
                c.profiles = []
        if not c.profiles:
            c.profiles = [{"name": "anonymous"}]
            if c.auth_user or c.auth_token or c.auto_register:
                c.profiles.append({"name": "user", "username": c.auth_user, "password": c.auth_pass, "token": c.auth_token})
        return c
