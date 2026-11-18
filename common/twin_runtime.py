"""Deterministyczny runtime bliźniaka (NIE generowany przez LLM). Kopiowany do artefaktu obok main.py.

main.py importuje: Base, SessionLocal, engine, get_db, init_twin.
init_twin(app) -> create_all + wczytanie seed.json + middleware nagłówków + handler walidacji.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import JSON, create_engine, event, insert
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

log = logging.getLogger("twin_runtime")
BASE_DIR = Path(__file__).resolve().parent
DB_URL = os.getenv("TWIN_DB_URL", "sqlite://")

_kwargs: Dict[str, Any] = {}
if DB_URL.startswith("sqlite"):
    _kwargs = {"connect_args": {"check_same_thread": False}}
    if DB_URL in ("sqlite://", "sqlite:///:memory:"):
        _kwargs["poolclass"] = StaticPool  # jedna wspólna baza in-memory => deterministyczny reset przy restarcie

engine = create_engine(DB_URL, **_kwargs)
if DB_URL.startswith("sqlite") and os.getenv("TWIN_FK", "0") == "1":
    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _):  # pragma: no cover
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _load_json(name: str, default: Any) -> Any:
    p = BASE_DIR / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        log.warning("Niepoprawny JSON: %s", name)
        return default


def load_seed() -> None:
    seed = _load_json("seed.json", {})
    tables = {t.lower(): t for t in Base.metadata.tables}
    for tname, rows in seed.items():
        real = tables.get(tname.lower())
        if real is None:
            log.warning("seed: brak tabeli %s w modelach", tname)
            continue
        table = Base.metadata.tables[real]
        cols = {c.name: c for c in table.columns}
        ok = 0
        for row in rows:
            vals = {}
            for k, v in row.items():
                if k not in cols:
                    continue
                if isinstance(v, (dict, list)) and not isinstance(cols[k].type, JSON):
                    v = json.dumps(v, ensure_ascii=False)
                vals[k] = v
            if not vals:
                continue
            try:
                with engine.begin() as conn:
                    conn.execute(insert(table).values(**vals))
                ok += 1
            except Exception as e:  # noqa: BLE001
                log.debug("seed %s: pominięto wiersz (%s)", tname, str(e)[:100])
        log.info("seed %s: %d/%d wierszy", tname, ok, len(rows))


def init_twin(app: FastAPI) -> None:
    Base.metadata.create_all(engine)
    load_seed()
    cfg = _load_json("headers.json", {})
    const: Dict[str, str] = cfg.get("constant", {})
    jct = cfg.get("json_content_type")
    vstatus = int(cfg.get("validation_status", 422))

    @app.middleware("http")
    async def _twin_headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in const.items():
            if k not in resp.headers:
                resp.headers[k] = v
        ct = resp.headers.get("content-type", "")
        if jct and ct.startswith("application/json") and ct != jct:
            resp.headers["content-type"] = jct
        return resp

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        detail = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "")} for e in exc.errors()]
        return JSONResponse(status_code=vstatus, content={"error": "validation", "detail": detail})
