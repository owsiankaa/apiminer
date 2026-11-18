"""Agent syntetyzujący: IR (deterministyczny) -> schema (LLM + walidacja) -> main.py (LLM) -> wewnętrzny CEGIS (TestClient)."""
from __future__ import annotations

import ast
import json
import os
import shutil
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import codecheck, diffing, repair  # noqa: E402
from common.ir import ApiModel  # noqa: E402
from common.llm import LLMError, OllamaClient, extract_tag  # noqa: E402
from common.logs import get_logger  # noqa: E402
from common.traffic import load_exchanges  # noqa: E402

log = get_logger("synthesizer")
DATA = os.getenv("DATA_DIR", "/data")
OUT = os.path.join(DATA, "generated_twin")
MAX_INNER = int(os.getenv("INNER_CEGIS_ITERS", "4"))
HERE = os.path.dirname(os.path.abspath(__file__))

DOCKERFILE = """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD python -c "import socket;socket.create_connection(('127.0.0.1',8000),2).close()" || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-access-log"]
"""
REQUIREMENTS = "fastapi>=0.110\nuvicorn>=0.29\nsqlalchemy>=2.0\npydantic>=2.5\nemail-validator\npython-multipart\n"


def wait_for_pipeline() -> None:
    flags = [os.path.join(DATA, "explorer_done.flag"), os.path.join(DATA, "collector_done.flag")]
    log.info("Czekam na explorer + kolektor eBPF…")
    t0 = time.time()
    while not all(os.path.exists(f) for f in flags):
        if time.time() - t0 > float(os.getenv("PIPELINE_TIMEOUT_S", "1800")):
            raise TimeoutError("Timeout oczekiwania na explorer/collector")
        time.sleep(1.0)
    with open(flags[0], encoding="utf-8") as f:
        if "failed" in f.read():
            log.warning("Explorer zgłosił błąd – kontynuuję na tym, co zebrano.")


def validate_sql(ddl: str) -> Optional[str]:
    try:
        con = sqlite3.connect(":memory:")
        con.executescript(ddl)
        con.close()
        return None
    except sqlite3.Error as e:
        return str(e)


def stage_schema(llm: OllamaClient, model: ApiModel, heuristic: str) -> str:
    ddl = heuristic
    if os.getenv("LLM_SCHEMA_REVIEW", "1") == "0" or len(heuristic) > 7000:
        log.info("Pomijam LLM-review schematu (DDL %d znaków / LLM_SCHEMA_REVIEW=0) – używam IR.", len(heuristic))
        return heuristic
    budget_chars = int(llm.prompt_budget_tokens * 3.2 * 0.85)
    prompt = repair.schema_prompt(model.digest(max(1500, min(9000, budget_chars - len(heuristic) - 1500))), heuristic)
    for attempt in range(1, 3):
        try:
            cand = llm.generate_tagged(prompt, "sql", system=repair.SYSTEM, label=f"schema#{attempt}")
        except LLMError as e:
            log.error("LLM (schema) niedostępny: %s – używam schematu heurystycznego", e)
            return heuristic
        err = validate_sql(cand)
        if not err:
            tables_h = {r.name for r in model.resources.values()}
            lost = [t for t in tables_h if f'"{t}"' not in cand and t not in cand]
            if lost:
                log.warning("LLM pominął tabele %s – dołączam z heurystyki", lost)
                cand = cand.rstrip() + "\n\n" + heuristic
                if validate_sql(cand):
                    return heuristic
            return cand
        log.warning("Schemat LLM niepoprawny (%s) – naprawa", err)
        prompt += f"\n\nYour previous DDL failed in SQLite: {err}\nReturn corrected DDL in <sql></sql>."
    log.warning("Fallback do schematu heurystycznego")
    return ddl


def write_artifacts(out: str, code: str, ddl: str, model: ApiModel) -> None:
    os.makedirs(out, exist_ok=True)
    shutil.copy(os.path.join(HERE, "common", "twin_runtime.py"), os.path.join(out, "twin_runtime.py"))
    files = {
        "main.py": code, "schema.sql": ddl, "Dockerfile": DOCKERFILE, "requirements.txt": REQUIREMENTS,
        "openapi.json": json.dumps(model.openapi(), indent=2, ensure_ascii=False),
        "seed.json": json.dumps(model.seed(), ensure_ascii=False),
        "headers.json": json.dumps(model.headers_cfg, ensure_ascii=False, indent=2),
        "ir_digest.txt": model.digest(30000),
        ".dockerignore": "__pycache__\n*.pyc\n",
    }
    for name, text in files.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")


def evaluate(out: str, code: str, openapi: Dict[str, Any], cases: List[Dict[str, Any]], known_tables: List[str]) -> Dict[str, Any]:
    """Jedna iteracja walidacji: lint -> import/trasy -> replay obserwowanych żądań przez TestClient."""
    result: Dict[str, Any] = {"static": codecheck.lint(code), "import_error": "", "missing_routes": [], "cases": [], "score": None, "analysis": None}
    if any(s.startswith("SyntaxError") for s in result["static"]):
        return result
    info = codecheck.inspect_twin(out)
    if not info["ok"]:
        result["import_error"] = info["error"]
        return result
    result["missing_routes"] = codecheck.missing_routes(openapi, info["routes"])
    try:
        actual = codecheck.replay(out, cases)
    except RuntimeError as e:
        result["import_error"] = f"Replay failed: {e}"
        return result
    for c, a in zip(cases, actual):
        twin = diffing.make_resp(a["status"], a["headers"], a["text"], a["data"], a.get("traceback", ""))
        issues = diffing.compare(c["expected"], twin)
        c = dict(c)
        c.update(actual=twin, issues=[i.as_dict() for i in issues], twin_traceback=a.get("traceback", ""))
        result["cases"].append(c)
    result["score"] = diffing.score(result["cases"])
    result["analysis"] = diffing.analyze_cases(result["cases"], known_tables=known_tables)
    return result


def main() -> None:
    t_start = time.time()
    wait_for_pipeline()
    exchanges = load_exchanges(os.path.join(DATA, "exchanges.jsonl"))
    if not exchanges:
        raise RuntimeError("Brak wymian API w exchanges.jsonl – sprawdź logi ebpf_sniffer/explorer (TLS? zły port?).")
    hints: List[str] = []
    hp = os.path.join(DATA, "static_api_hints.json")
    if os.path.exists(hp):
        with open(hp, encoding="utf-8") as f:
            hints = json.load(f)
    model = ApiModel(exchanges, hints)
    log.info("IR: %s", json.dumps(model.summary(), ensure_ascii=False))
    heuristic = model.ddl()
    openapi = model.openapi()
    tables = [r.name for r in model.resources.values()]
    route_list = "\n".join(f"{m.upper()} {p}" for p, ops in openapi["paths"].items() for m in ops)

    llm = OllamaClient()
    llm.ensure_ready()
    log.info("Etap 1/3: schemat bazy (IR + LLM + walidacja SQLite)…")
    ddl = stage_schema(llm, model, heuristic)

    log.info("Etap 2/3: generacja main.py…")
    code = llm.generate_tagged(repair.codegen_prompt(model.digest(max(2000, min(14000, int(llm.prompt_budget_tokens * 3.2 * 0.85) - len(ddl) - len(route_list) - len(repair.CONTRACT) - 500))), ddl, route_list), "python", system=repair.SYSTEM, label="codegen")

    log.info("Etap 3/3: wewnętrzny CEGIS (TestClient, %d iteracji max)…", MAX_INNER)
    cases = diffing.cases_from_exchanges(exchanges, 150) + diffing.derive_probe_cases(exchanges, 40)
    # probes nie mają 'expected' – bierzemy tylko obserwowane do wewnętrznej oceny
    cases = [c for c in cases if "expected" in c]
    history: List[Dict[str, Any]] = []
    best = {"pct": -1.0, "code": code}
    stagnation = 0
    for it in range(1, MAX_INNER + 2):
        code, notes = codecheck.autofix(code)
        try:
            ast.parse(code)
        except SyntaxError as e:
            notes.append(f"SyntaxError line {e.lineno}")
        write_artifacts(OUT, code, ddl, model)
        ev = evaluate(OUT, code, openapi, cases, tables)
        pct = ev["score"]["lenient_pct"] if ev["score"] else 0.0
        history.append({"iter": it, "autofix": notes, "lint": ev["static"], "import_error": ev["import_error"][:300],
                        "missing_routes": len(ev["missing_routes"]), "score": ev["score"]})
        log.info("iter %d: lenient=%.1f%% brakujących tras=%d lint=%d %s", it, pct, len(ev["missing_routes"]), len(ev["static"]), "IMPORT ERR" if ev["import_error"] else "")
        if pct > best["pct"]:
            best, stagnation = {"pct": pct, "code": code}, 0
        else:
            stagnation += 1
        if (pct >= 100.0 and not ev["missing_routes"]) or it > MAX_INNER or stagnation >= 2:
            break
        extra = "\n".join(ev["static"] + [f"IMPORT/RUNTIME ERROR:\n{ev['import_error']}"] * bool(ev["import_error"])
                          + [f"Missing route: {r}" for r in ev["missing_routes"][:20]])
        analysis_text = diffing.render_analysis(ev["analysis"]) if ev["analysis"] else "(no replay – fix static/import errors first)"
        regress = "" if pct >= best["pct"] else "The previous attempt scored WORSE than the best version; you were given the best version – avoid the same mistake."
        prompt = repair.repair_prompt(best["code"], ddl, analysis_text, "", model.digest(5000), llm.prompt_budget_tokens, extra, regress)
        try:
            code = llm.generate_tagged(prompt, "python", system=repair.SYSTEM, label=f"repair#{it}")
        except LLMError as e:
            log.error("LLM padł w naprawie: %s", e)
            break
    code = best["code"]
    code, _ = codecheck.autofix(code)
    write_artifacts(OUT, code, ddl, model)
    report = {"model": llm.model, "seconds": round(time.time() - t_start, 1), "ir": model.summary(), "history": history,
              "best_lenient_pct": best["pct"], "num_ctx": llm.num_ctx, "num_predict": llm.num_predict}
    with open(os.path.join(DATA, "synthesis_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info("SUKCES. Artefakty: %s | najlepszy wynik offline: %.1f%%", OUT, best["pct"])


if __name__ == "__main__":
    try:
        main()
        open(os.path.join(DATA, "synthesizer_done.flag"), "w").write("ok\n")
    except Exception:
        log.exception("Synthesizer zakończył się błędem")
        open(os.path.join(DATA, "synthesizer_failed.flag"), "w").write("failed\n")
        sys.exit(1)
