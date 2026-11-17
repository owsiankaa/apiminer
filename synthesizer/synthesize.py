import ast
import json
import os
import re
import subprocess
import tempfile
import time
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:14b")
TRAFFIC_FILE = "/data/traffic.jsonl"
DONE_FLAG = "/data/explorer_done.flag"
OUT_DIR = "/data/generated_twin"


def wait_for_explorer():
    print("[Synthesizer] Oczekuję na zakończenie autonomicznej eksploracji (explorer)...")
    while not os.path.exists(DONE_FLAG):
        time.sleep(1.0)
    time.sleep(2.0)

    if not os.path.exists(TRAFFIC_FILE):
        raise FileNotFoundError("Brak pliku traffic.jsonl - eBPF nie zapisał ruchu.")
    with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def ask_ollama(prompt: str) -> str:
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 8192},
        },
        timeout=600,
    )
    resp.raise_for_status()
    return resp.json()["response"]


def extract_tag(text: str, tag: str) -> str:
    match = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
    content = match.group(1).strip() if match else text.strip()
    content = re.sub(r"^```[a-zA-Z0-9]*\n?", "", content)
    content = re.sub(r"\n?```$", "", content)
    return content.strip()


def compact_json_value(val, depth=0):
    if depth > 4:
        return "..."
    if isinstance(val, list):
        return [compact_json_value(x, depth + 1) for x in val[:2]]
    if isinstance(val, dict):
        return {k: compact_json_value(v, depth + 1) for k, v in list(val.items())[:25]}
    if isinstance(val, str) and len(val) > 100:
        return val[:100] + "..."
    return val


def compact_http_frame(raw_http: str) -> str:
    if "\r\n\r\n" not in raw_http:
        return raw_http[:600]
    headers, body = raw_http.split("\r\n\r\n", 1)
    first_line = headers.splitlines()[0] if headers.splitlines() else ""
    body_clean = body.strip()
    if body_clean:
        try:
            parsed = json.loads(body_clean)
            body_clean = json.dumps(compact_json_value(parsed), ensure_ascii=False)
        except Exception:
            body_clean = body_clean[:400]
    return f"{first_line}\n{body_clean}"


def deduplicate_traces(records: list[dict]) -> str:
    seen_signatures = set()
    selected = []
    last_req_sig = None

    for r in records:
        if r["direction"] == "request":
            sig = f"{r.get('method')} {r.get('endpoint_template')}"
            last_req_sig = sig
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                selected.append(f"[REQUEST | {sig}]\n{compact_http_frame(r['raw_http'])}")
        elif r["direction"] == "response" and last_req_sig:
            status_line = r["raw_http"].splitlines()[0] if r["raw_http"].splitlines() else ""
            res_sig = f"{last_req_sig} -> {status_line}"
            if res_sig not in seen_signatures:
                seen_signatures.add(res_sig)
                selected.append(f"[RESPONSE | {res_sig}]\n{compact_http_frame(r['raw_http'])}")

    return "\n---\n".join(selected[:30])


def validate_code_runtime(code: str) -> str | None:
    if not code:
        return "Pusty kod Pythona"
    try:
        ast.parse(code)
    except SyntaxError as e:
        return f"SyntaxError w linii {e.lineno}: {e.msg}"

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test_twin.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(code)
        res = subprocess.run(
            ["python3", "-c", "import sys; sys.path.insert(0, '.'); import test_twin"],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            err_lines = res.stderr.strip().splitlines()
            return "\n".join(err_lines[-6:])
    return None


def main():
    records = wait_for_explorer()
    condensed_log = deduplicate_traces(records)
    print(f"[Synthesizer] Przetworzono {len(records)} komunikatów eBPF -> skompresowano unikalne kontrakty API.")

    print(f"[Synthesizer] Etap 1/2: Inferencja OpenAPI 3.1 i schematu bazy danych ({MODEL_NAME})...")
    stage1_prompt = f"""Jesteś architektem oprogramowania. Na podstawie skompresowanego ruchu HTTP przechwyconego metodą czarnej skrzynki wygeneruj:
1. Zwięzłą specyfikację OpenAPI 3.1 (JSON) dla wszystkich wykrytych ścieżek i metod HTTP (zachowaj dokładne ścieżki `/api/...` i `/rest/...`, trailing slashes oraz kody odpowiedzi np. 200, 201, 401).
2. Schemat bazy danych SQLite (DDL CREATE TABLE) dla wszystkich zasobów, uwzględniając kolumny używane w parametrach zapytań (np. `name`, `q`, `category`).

PRZECHWYCONY RUCH HTTP:
{condensed_log}

Zwróć odpowiedź DOKŁADNIE w tych dwóch tagach XML:
<openapi>
JSON OpenAPI 3.1
</openapi>
<sql>
kod SQL CREATE TABLE ...
</sql>"""

    stage1_raw = ask_ollama(stage1_prompt)
    openapi_spec = extract_tag(stage1_raw, "openapi")
    sql_code = extract_tag(stage1_raw, "sql")

    print(f"[Synthesizer] Etap 2/2: Generowanie kodu backendu FastAPI + SQLAlchemy...")
    stage2_prompt = f"""Na podstawie poniższej specyfikacji OpenAPI 3.1 i schematu SQL wygeneruj kompletny plik `main.py` w Pythonie (FastAPI + SQLite + SQLAlchemy).

KRYTYCZNE WYMAGANIA (BEZWZGLĘDNIE PRZESTRZEGAJ):
1. Zaimplementuj WSZYSTKIE ścieżki i metody HTTP ze specyfikacji OpenAPI (zachowaj dokładne ukośniki końcowe np. `/api/Challenges/`).
2. Endpointy listujące kolekcje (`GET` bez ID na końcu) NIGDY nie mogą zwracać 404 gdy tabela jest pusta! Zawsze zwracaj status 200 z pustą listą (np. `[]` lub `{{"status": "success", "data": []}}` zgodnie ze specyfikacją).
3. W funkcji `@app.on_event("startup")` zainicjalizuj po 2 przykładowe rekordy w KAŻDEJ tabeli zdefiniowanej w bazie (nie tylko w pierwszych dwóch!).
4. Jeśli endpoint używa parametru `Query` (np. `name`, `q`, `fields`), upewnij się, że używasz `getattr(Model, field_name, None)` lub że taka kolumna istnieje w modelu SQLAlchemy, aby uniknąć `AttributeError` (HTTP 500).
5. Jeśli w specyfikacji endpoint zwracał `401` (np. nieudane logowanie), zwróć `JSONResponse(status_code=401, content=...)` lub `Response(status_code=401, content=...)`.
6. Oddziel modele SQLAlchemy (`Base`) od schematów Pydantic (`BaseModel`).

SPECYFIKACJA OPENAPI 3.1:
{openapi_spec}

SCHEMAT SQL:
{sql_code}

Zwróć wyłącznie kompletny kod Pythona wewnątrz tagów <python>...</python>:
<python>
...
</python>"""

    stage2_raw = ask_ollama(stage2_prompt)
    py_code = extract_tag(stage2_raw, "python")

    for attempt in range(1, 4):
        err = validate_code_runtime(py_code)
        if not err:
            print(f"[Synthesizer] Walidacja AST i Runtime zakończona sukcesem (próba {attempt}).")
            break
        print(f"[Synthesizer] Wykryto błąd podczas weryfikacji:\n{err}\n-> Wysyłam do samonaprawy...")
        fix_prompt = f"""Popraw poniższy kod Python FastAPI, ponieważ zgłasza błąd:
{err}

Zwróć wyłącznie poprawiony kod wewnątrz tagów <python>...</python>.
<python>
{py_code}
</python>"""
        fixed_raw = ask_ollama(fix_prompt)
        py_code = extract_tag(fixed_raw, "python")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(f"{OUT_DIR}/openapi.json", "w", encoding="utf-8") as f:
        f.write(openapi_spec + "\n")
    with open(f"{OUT_DIR}/schema.sql", "w", encoding="utf-8") as f:
        f.write(sql_code + "\n")
    with open(f"{OUT_DIR}/main.py", "w", encoding="utf-8") as f:
        f.write(py_code + "\n")
    with open(f"{OUT_DIR}/Dockerfile", "w", encoding="utf-8") as f:
        f.write(
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            "RUN pip install --no-cache-dir fastapi uvicorn sqlalchemy pydantic\n"
            "COPY main.py .\n"
            'CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]\n'
        )

    print(f"[Synthesizer] SUKCES! Wygenerowano artefakty w {OUT_DIR}")


if __name__ == "__main__":
    main()
