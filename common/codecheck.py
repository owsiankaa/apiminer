"""Statyczne i dynamiczne kontrole kodu bliźniaka: autofix Pydantic v2, lint, import + pokrycie tras, replay przez TestClient."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

RUNTIME_IMPORT = "from twin_runtime import Base, SessionLocal, engine, get_db, init_twin"


def autofix(code: str) -> Tuple[str, List[str]]:
    notes: List[str] = []
    c = code

    # 1) własny silnik/Base/sesja -> runtime
    patterns = [
        (r"^\s*from sqlalchemy\.ext\.declarative import declarative_base\s*$", ""),
        (r"^\s*Base\s*=\s*declarative_base\(\)\s*$", ""),
        (r"^\s*engine\s*=\s*create_engine\(.*\)\s*$", ""),
        (r"^\s*SessionLocal\s*=\s*sessionmaker\(.*\)\s*$", ""),
        (r"^\s*Base\.metadata\.create_all\(.*\)\s*$", ""),
        (r"^\s*DATABASE_URL\s*=.*$", ""),
    ]
    for rx, rep in patterns:
        new = re.sub(rx, rep, c, flags=re.M)
        if new != c:
            notes.append(f"usunięto własną definicję DB ({rx[:30]}…) -> twin_runtime")
            c = new
    if "from twin_runtime import" not in c:
        c = _insert_after_future(c, RUNTIME_IMPORT)
        notes.append("dodano import z twin_runtime")

    # 2) Pydantic v1 -> v2
    def _cfg(m: re.Match) -> str:
        notes.append("class Config -> model_config = ConfigDict(from_attributes=True)")
        return f"\n{m.group(1)}model_config = ConfigDict(from_attributes=True)\n"

    c = re.sub(r"\n([ \t]+)class Config:\s*\n(?:\1[ \t]+.*\n?)+", _cfg, c)
    for old, new in ((".from_orm(", ".model_validate("), (".parse_obj(", ".model_validate("), (".dict(", ".model_dump(")):
        if old in c:
            c = c.replace(old, new)
            notes.append(f"{old} -> {new}")
    if "ConfigDict" in c and not re.search(r"from pydantic import[^\n]*ConfigDict", c):
        c = _insert_after_future(c, "from pydantic import ConfigDict")
        notes.append("dodano import ConfigDict")

    # 3) FastAPI(...) – dokładne ścieżki, brak dokumentacji kolidującej z oryginałem
    m = re.search(r"\bapp\s*=\s*FastAPI\(([^)]*)\)", c)
    if m:
        inner, add = m.group(1), []
        for kw, val in (("redirect_slashes", "False"), ("docs_url", "None"), ("redoc_url", "None"), ("openapi_url", "None")):
            if kw not in inner:
                add.append(f"{kw}={val}")
        if add:
            new_inner = (inner.strip().rstrip(",") + ", " if inner.strip() else "") + ", ".join(add)
            c = c[: m.start(1)] + new_inner + c[m.end(1):]
            notes.append("FastAPI(...): " + ", ".join(add))

    # 4) init_twin(app) na końcu
    if "init_twin(app)" not in c:
        c = c.rstrip() + "\n\n\ninit_twin(app)\n"
        notes.append("dopisano init_twin(app)")
    return re.sub(r"\n{4,}", "\n\n\n", c).strip() + "\n", notes


def _insert_after_future(code: str, line: str) -> str:
    lines = code.splitlines()
    idx = 0
    for i, ln in enumerate(lines):
        if ln.startswith("from __future__"):
            idx = i + 1
    lines.insert(idx, line)
    return "\n".join(lines)


def lint(code: str) -> List[str]:
    problems: List[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"SyntaxError line {e.lineno}: {e.msg}"]
    if "orm_mode" in code:
        problems.append("Pydantic v1 'orm_mode' used – use model_config = ConfigDict(from_attributes=True)")
    if re.search(r"@(?:pydantic\.)?validator\(", code):
        problems.append("Pydantic v1 @validator used – use @field_validator")
    if "declarative_base()" in code:
        problems.append("Own declarative_base() – import Base from twin_runtime")
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    if "app" not in names:
        problems.append("No 'app' variable (FastAPI instance)")
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ("get", "post", "put", "patch", "delete") and d.args:
                    a0 = d.args[0]
                    if isinstance(a0, ast.Constant):
                        key = (d.func.attr, a0.value)
                        if key in seen:
                            problems.append(f"Duplicate route {d.func.attr.upper()} {a0.value}")
                        seen.add(key)
    return problems


_ROUTES_SCRIPT = r'''
import json, os, sys, traceback
sys.path.insert(0, ".")
os.environ.setdefault("TWIN_DB_URL", "sqlite://")
try:
    import importlib
    m = importlib.import_module("main")
    app = getattr(m, "app")
    out = [{"path": getattr(r, "path", ""), "methods": sorted(getattr(r, "methods", None) or [])} for r in app.routes]
    print("__ROUTES__" + json.dumps(out))
except BaseException:
    print("__ERROR__" + traceback.format_exc()[-1800:])
'''

_REPLAY_SCRIPT = r'''
import json, os, sys, traceback
sys.path.insert(0, ".")
os.environ.setdefault("TWIN_DB_URL", "sqlite://")
cases = json.load(open(sys.argv[1], encoding="utf-8"))
try:
    from fastapi.testclient import TestClient
    import main
    results = []
    with TestClient(main.app, raise_server_exceptions=True) as c:
        for case in cases:
            try:
                kw = {"headers": case.get("headers") or {}}
                if case.get("payload") is not None:
                    kw["json"] = case["payload"]
                elif case.get("raw"):
                    kw["content"] = case["raw"]
                r = c.request(case["method"], case["path"], **kw)
                text = r.text
                try:
                    data = r.json() if "json" in r.headers.get("content-type", "") else None
                except ValueError:
                    data = None
                results.append({"status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()}, "text": text[:2000], "data": data, "traceback": ""})
            except BaseException:
                results.append({"status": 500, "headers": {}, "text": "", "data": None, "traceback": traceback.format_exc()[-1500:]})
    print("__REPLAY__" + json.dumps(results, default=str))
except BaseException:
    print("__ERROR__" + traceback.format_exc()[-1800:])
'''


def _run_script(script: str, cwd: str, args: Optional[List[str]] = None, timeout: int = 90) -> Tuple[str, str]:
    try:
        p = subprocess.run([sys.executable, "-c", script] + (args or []), cwd=cwd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT: import/replay przekroczył limit czasu"
    return p.stdout, p.stderr


def inspect_twin(twin_dir: str) -> Dict[str, Any]:
    out, err = _run_script(_ROUTES_SCRIPT, twin_dir, timeout=60)
    m = re.search(r"__ROUTES__(.*)", out)
    if m:
        return {"ok": True, "routes": json.loads(m.group(1)), "error": ""}
    e = re.search(r"__ERROR__(.*)", out, re.S)
    return {"ok": False, "routes": [], "error": (e.group(1) if e else err or out)[-1800:]}


def _canon(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def missing_routes(openapi: Dict[str, Any], routes: List[Dict[str, Any]]) -> List[str]:
    have = {(_canon(r["path"]), m) for r in routes for m in r["methods"]}
    miss = []
    for path, ops in openapi.get("paths", {}).items():
        for method in ops:
            if (_canon(path), method.upper()) not in have:
                miss.append(f"{method.upper()} {path}")
    return miss


def replay(twin_dir: str, cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    slim = [{k: c.get(k) for k in ("method", "path", "payload", "raw", "headers")} for c in cases]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(slim, fh)
        tmp = fh.name
    try:
        out, err = _run_script(_REPLAY_SCRIPT, twin_dir, [tmp], timeout=180)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    m = re.search(r"__REPLAY__(.*)", out, re.S)
    if not m:
        e = re.search(r"__ERROR__(.*)", out, re.S)
        raise RuntimeError((e.group(1) if e else err or out)[-1500:])
    return json.loads(m.group(1))
