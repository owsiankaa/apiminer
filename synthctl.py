#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import time
import requests

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.prompt import Prompt, Confirm
    from rich import box
except ImportError:
    print("Zainstaluj zależności lokalnie: pip install rich requests")
    sys.exit(1)

console = Console()

TRAFFIC_FILE = "shared_data/traffic.jsonl"
TWIN_DIR = "shared_data/generated_twin"
ORIG_URL = "http://localhost:8080"
TWIN_URL = "http://localhost:8081"
OLLAMA_URL = "http://localhost:11434"
MODEL_NAME = "qwen2.5-coder:14b"


def run_cmd(cmd, capture=False):
    if capture:
        return subprocess.run(cmd, shell=True, text=True, capture_output=True)
    return subprocess.run(cmd, shell=True)


def banner():
    console.clear()
    console.print(
        Panel.fit(
            "[bold cyan]eBPF + LLM BLACKBOX API SYNTHESIZER[/bold cyan]\n"
            "[dim]PJATK MSc Research Console | Target: :8080 | Twin: :8081[/dim]",
            border_style="bright_blue",
            box=box.DOUBLE,
        )
    )


def status_bar():
    res = run_cmd("docker ps --format '{{.Names}}\t{{.Status}}'", capture=True)
    lines = res.stdout.strip().splitlines()
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    table.add_column("Kontener", style="cyan")
    table.add_column("Status", style="green")

    if not lines:
        table.add_row("Brak aktywnych kontenerów", "[red]OFFLINE[/red]")
    else:
        for line in lines:
            parts = line.split("\t")
            if len(parts) == 2:
                table.add_row(parts[0], parts[1])

    traffic_count = 0
    if os.path.exists(TRAFFIC_FILE):
        with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
            traffic_count = sum(1 for _ in f)

    twin_ready = "[bold green]GOTOWY[/bold green]" if os.path.exists(f"{TWIN_DIR}/main.py") else "[yellow]BRAK[/yellow]"
    console.print(table)
    console.print(
        f" Przechwycone ramki eBPF: [bold yellow]{traffic_count}[/bold yellow]  |  "
        f"Artefakt Digital Twin: {twin_ready}\n"
    )


def action_run_pipeline():
    console.print("[bold yellow][*] Resetuję poprzedni stan i uruchamiam pełny pipeline...[/bold yellow]")
    run_cmd("docker rm -f digital_twin >/dev/null 2>&1")
    run_cmd("docker compose down >/dev/null 2>&1")
    run_cmd(f"rm -rf {TRAFFIC_FILE} {TWIN_DIR} shared_data/explorer_done.flag")
    os.makedirs("shared_data", exist_ok=True)

    run_cmd("docker compose up -d --build")
    console.print("[bold green][+] Kontenery wystartowały. Śledzę logi na żywo (Ctrl+C wraca do menu)...[/bold green]\n")
    try:
        run_cmd("docker compose logs -f ebpf_sniffer explorer synthesizer")
    except KeyboardInterrupt:
        pass


def action_inspect_traffic():
    if not os.path.exists(TRAFFIC_FILE):
        console.print("[red][!] Brak pliku traffic.jsonl. Uruchom najpierw pipeline (opcja 1).[/red]")
        Prompt.ask("\nWciśnij Enter")
        return

    with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    table = Table(title="Przechwycony ruch HTTP (Kernel eBPF TC RingBuffer)", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("Kierunek", width=10)
    table.add_column("Porty", width=13)
    table.add_column("Pierwsza linia / Payload", style="white")

    for idx, r in enumerate(records, 1):
        direction = "[cyan]REQ ->[/cyan]" if r["direction"] == "request" else "[green]<- RES[/green]"
        ports = f"{r['sport']}->{r['dport']}"
        lines = r["raw_http"].splitlines()
        summary = lines[0] if lines else ""
        if "\r\n\r\n" in r["raw_http"]:
            body = r["raw_http"].split("\r\n\r\n", 1)[1].strip()
            if body:
                summary += f" [dim]| {body[:70]}[/dim]"
        table.add_row(str(idx), direction, ports, summary)

    console.print(table)
    Prompt.ask("\nWciśnij Enter, aby wrócić")


def action_inspect_twin_code():
    openapi_path = f"{TWIN_DIR}/openapi.json"
    sql_path = f"{TWIN_DIR}/schema.sql"
    py_path = f"{TWIN_DIR}/main.py"

    if not os.path.exists(py_path):
        console.print("[red][!] Digital Twin nie został jeszcze wygenerowany.[/red]")
        Prompt.ask("\nWciśnij Enter")
        return

    if os.path.exists(openapi_path):
        with open(openapi_path, "r", encoding="utf-8") as f:
            console.print(Panel(Syntax(f.read(), "json", theme="monokai", line_numbers=True), title="Wywnioskowana specyfikacja OpenAPI 3.1 (LLM)"))

    if os.path.exists(sql_path):
        with open(sql_path, "r", encoding="utf-8") as f:
            console.print(Panel(Syntax(f.read(), "sql", theme="monokai", line_numbers=True), title="Wygenerowany schemat SQL (LLM)"))

    with open(py_path, "r", encoding="utf-8") as f:
        console.print(Panel(Syntax(f.read(), "python", theme="monokai", line_numbers=True), title="Wygenerowany kod FastAPI (Digital Twin)"))

    Prompt.ask("\nWciśnij Enter, aby wrócić")


def rebuild_and_start_twin() -> bool:
    run_cmd("docker rm -f digital_twin >/dev/null 2>&1")
    res = run_cmd(f"docker build -t api-digital-twin {TWIN_DIR} >/dev/null 2>&1")
    if res.returncode != 0:
        return False
    run_cmd("docker run -d --name digital_twin -p 8081:8000 api-digital-twin >/dev/null 2>&1")
    time.sleep(2.5)
    return True


def action_deploy_twin():
    if not os.path.exists(f"{TWIN_DIR}/Dockerfile"):
        console.print("[red][!] Brak plików w shared_data/generated_twin/.[/red]")
        Prompt.ask("\nWciśnij Enter")
        return

    console.print("[bold cyan][*] Buduję i uruchamiam kontener Digital Twin na porcie 8081...[/bold cyan]")
    if not rebuild_and_start_twin():
        console.print("[red][!] Błąd budowania obrazu bliźniaka.[/red]")
        Prompt.ask("\nWciśnij Enter")
        return

    console.print("[bold green][+] Digital Twin działa pod adresem http://localhost:8081[/bold green]")
    Prompt.ask("\nWciśnij Enter, aby wrócić")


def parse_response_safe(resp):
    try:
        return resp.json(), "json"
    except Exception:
        return resp.text.strip(), "text"


def run_differential_suite():
    with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    seen = set()
    dynamic_cases = []
    for r in records:
        if r.get("direction") != "request":
            continue
        method = r.get("method")
        path = r.get("path")
        if not method or not path:
            continue
        sig = f"{method} {path}"
        if sig in seen:
            continue
        seen.add(sig)

        body = None
        if "\r\n\r\n" in r["raw_http"]:
            raw_body = r["raw_http"].split("\r\n\r\n", 1)[1].strip()
            if raw_body:
                try:
                    body = json.loads(raw_body)
                except Exception:
                    body = None
        dynamic_cases.append((method, path, body))

    table = Table(title="Autonomiczny Raport Zgodności Behawioralnej (Differential Testing)", box=box.DOUBLE_EDGE)
    table.add_column("Metoda + Endpoint", style="cyan")
    table.add_column("Orig", justify="center")
    table.add_column("Twin", justify="center")
    table.add_column("Struktura / Wynik", style="white")

    matches = 0
    diffs = []

    for method, path, payload in dynamic_cases:
        try:
            r_orig = requests.request(method, f"{ORIG_URL}{path}", json=payload, timeout=4)
            orig_status = str(r_orig.status_code)
            orig_data, orig_kind = parse_response_safe(r_orig)
        except Exception as e:
            orig_status, orig_data, orig_kind = "CONN_ERR", str(e), "err"

        try:
            r_twin = requests.request(method, f"{TWIN_URL}{path}", json=payload, timeout=4)
            twin_status = str(r_twin.status_code)
            twin_data, twin_kind = parse_response_safe(r_twin)
        except Exception as e:
            twin_status, twin_data, twin_kind = "CONN_ERR", str(e), "err"

        is_match = (
            orig_status == twin_status
            and orig_kind == twin_kind
            and type(orig_data) is type(twin_data)
        )
        if is_match:
            matches += 1
        else:
            diffs.append({
                "endpoint": f"{method} {path}",
                "request_payload": payload,
                "expected_status": orig_status,
                "expected_sample": json.dumps(orig_data, ensure_ascii=False)[:250] if orig_kind == "json" else orig_data[:250],
                "actual_twin_status": twin_status,
                "actual_twin_output": json.dumps(twin_data, ensure_ascii=False)[:250] if twin_kind == "json" else twin_data[:250],
            })

        verdict = "[bold green]MATCH[/bold green]" if is_match else "[bold red]DIFF[/bold red]"
        preview = (json.dumps(twin_data, ensure_ascii=False) if twin_kind == "json" else str(twin_data))[:58]
        table.add_row(f"{method} {path}", orig_status, twin_status, f"{verdict} | {preview}")

    console.print(table)
    pct = (matches / max(1, len(dynamic_cases))) * 100
    console.print(f"\n[bold]Wynik zgodności behawioralnej:[/bold] [cyan]{matches}/{len(dynamic_cases)}[/cyan] ({pct:.1f}%)")
    return diffs


def cegis_refine_twin(diffs: list[dict]):
    """Pętla CEGIS: wysyła kontrprzykłady z Differential Testingu do LLM i aktualizuje Digital Twin."""
    py_path = f"{TWIN_DIR}/main.py"
    with open(py_path, "r", encoding="utf-8") as f:
        current_code = f.read()

    diff_report = json.dumps(diffs[:12], indent=2, ensure_ascii=False)
    console.print(f"\n[bold yellow][*] Wysyłam {len(diffs)} kontrprzykładów (DIFF) do modelu {MODEL_NAME} w celu auto-korekty...[/bold yellow]")

    prompt = f"""Jesteś ekspertem FastAPI. Poniższy kod Cyfrowego Bliźniaka przeszedł testy porównawcze z aplikacją docelową i wykazał następujące rozbieżności (kontrprzykłady DIFF):

RAPORT ROZBIEŻNOŚCI (DIFF):
{diff_report}

ZADANIE:
Zmodyfikuj poniższy plik `main.py`, aby wyeliminować WSZYSTKIE powyższe rozbieżności:
- Dopasuj kody statusu HTTP (`expected_status`) oraz strukturę JSON/tekstową (`expected_sample`) do oryginału.
- Upewnij się, że żaden endpoint nie rzuca błędu 500 (np. z powodu brakującej kolumny w filtrze zapytania).
- Zwróć wyłącznie kompletny, zaktualizowany kod Pythona wewnątrz tagów <python>...</python>.

AKTUALNY KOD main.py:
<python>
{current_code}
</python>"""

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
    raw = resp.json()["response"]
    match = re.search(r"<python>(.*?)</python>", raw, re.DOTALL)
    new_code = match.group(1).strip() if match else raw.strip()
    new_code = re.sub(r"^```[a-zA-Z0-9]*\n?", "", new_code)
    new_code = re.sub(r"\n?```$", "", new_code).strip()

    with open(py_path, "w", encoding="utf-8") as f:
        f.write(new_code + "\n")

    console.print("[bold cyan][*] Przebudowuję i restartuję kontener Digital Twin (:8081)...[/bold cyan]")
    if rebuild_and_start_twin():
        console.print("[bold green][+] Bliźniak zaktualizowany! Uruchamiam ponowny test porównawczy...[/bold green]\n")
        run_differential_suite()
    else:
        console.print("[red][!] Błąd budowania zaktualizowanego kontenera.[/red]")


def action_differential_test():
    if not os.path.exists(TRAFFIC_FILE):
        console.print("[red][!] Brak pliku traffic.jsonl. Uruchom najpierw pipeline (opcja 1).[/red]")
        Prompt.ask("\nWciśnij Enter")
        return

    console.print("[bold magenta][*] Generuję dynamiczny zestaw testów Blackbox na podstawie traffic.jsonl...[/bold magenta]\n")
    diffs = run_differential_suite()

    if diffs:
        if Confirm.ask(f"\n[bold yellow]Wykryto {len(diffs)} rozbieżności (DIFF). Uruchomić pętlę samonaprawy CEGIS na podstawie tabeli?[/bold yellow]", default=True):
            cegis_refine_twin(diffs)

    Prompt.ask("\nWciśnij Enter, aby wrócić")


def action_interactive_curl():
    console.print("[bold cyan]Tryb ręcznych zapytań do Cyfrowego Bliźniaka (:8081)[/bold cyan]")
    method = Prompt.ask("Metoda HTTP", choices=["GET", "POST", "PATCH", "DELETE"], default="GET")
    path = Prompt.ask("Ścieżka", default="/rest/admin/application-version")
    body = None
    if method in ["POST", "PATCH"]:
        raw = Prompt.ask("JSON Body (puste jeśli brak)", default='{"email": "test@juice-sh.op", "password": "123"}')
        if raw.strip():
            body = json.loads(raw)

    try:
        r = requests.request(method, f"{TWIN_URL}{path}", json=body, timeout=5)
        console.print(f"\n[bold green]HTTP {r.status_code}[/bold green]")
        data, kind = parse_response_safe(r)
        if kind == "json":
            console.print(Syntax(json.dumps(data, indent=2, ensure_ascii=False), "json", theme="monokai"))
        else:
            console.print(data)
    except Exception as e:
        console.print(f"[red]Błąd: {e}[/red]")

    Prompt.ask("\nWciśnij Enter, aby wrócić")


def main():
    while True:
        banner()
        status_bar()
        console.print("[bold]Wybierz akcję:[/bold]")
        console.print("  [cyan][1][/cyan] Odpal cały pipeline (Target -> eBPF -> Playwright -> Ollama)")
        console.print("  [cyan][2][/cyan] Podgląd pakietów przechwyconych przez eBPF (traffic.jsonl)")
        console.print("  [cyan][3][/cyan] Podgląd OpenAPI, SQL i FastAPI (Digital Twin)")
        console.print("  [cyan][4][/cyan] Zbuduj i uruchom kontener Digital Twin (:8081)")
        console.print("  [cyan][5][/cyan] Autonomiczny test porównawczy + Samonaprawa CEGIS (:8080 vs :8081)")
        console.print("  [cyan][6][/cyan] Własne zapytanie HTTP do Bliźniaka (interaktywny curl)")
        console.print("  [cyan][0][/cyan] Wyjście\n")

        choice = Prompt.ask("Opcja", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")

        if choice == "1":
            action_run_pipeline()
        elif choice == "2":
            action_inspect_traffic()
        elif choice == "3":
            action_inspect_twin_code()
        elif choice == "4":
            action_deploy_twin()
        elif choice == "5":
            action_differential_test()
        elif choice == "6":
            action_interactive_curl()
        elif choice == "0":
            break


if __name__ == "__main__":
    main()
