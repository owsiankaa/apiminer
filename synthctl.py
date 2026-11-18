#!/usr/bin/env python3
"""Konsola badawcza: pipeline, inspekcja, deploy bliźniaka, differential testing, CEGIS, benchmark, raport.

Użycie: python synthctl.py            (menu)
        python synthctl.py run|deploy|test|cegis|bench|report|doctor
Działa na Windows / Linux / macOS (bez shell=True, ścieżki przez pathlib).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    import requests
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
    from rich.table import Table
except ImportError:
    print("Zainstaluj zależności: pip install rich requests")
    sys.exit(1)

from common import codecheck, diffing, repair  # noqa: E402
from common.ir import ApiModel  # noqa: E402
from common.llm import LLMError, OllamaClient  # noqa: E402
from common.logs import get_logger  # noqa: E402
from common.traffic import load_exchanges  # noqa: E402

console = Console()
log = get_logger("synthctl")

DATA = ROOT / "shared_data"
EXCHANGES = DATA / "exchanges.jsonl"
TWIN_DIR = DATA / "generated_twin"
ORIG_URL = os.getenv("ORIG_URL", "http://localhost:8080")
TWIN_URL = os.getenv("TWIN_URL", "http://localhost:8081")
OLLAMA_URL = os.getenv("OLLAMA_URL_HOST", "http://localhost:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:14b")
MAX_CEGIS = int(os.getenv("MAX_CEGIS_ITERS", "5"))
REQ_TIMEOUT = float(os.getenv("REQ_TIMEOUT", "6"))
DIFF_SAFE = os.getenv("DIFF_SAFE", "0") == "1"  # 1 => nie wysyłaj DELETE/PUT/PATCH do oryginału


# ----------------------------------------------------------------------------- narzędzia
def run(args: List[str], capture: bool = True, timeout: Optional[int] = None, check: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, cwd=ROOT, capture_output=capture, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=check)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", f"Nie znaleziono polecenia: {args[0]}")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timeout")


def compose_cmd() -> List[str]:
    if shutil.which("docker") and run(["docker", "compose", "version"]).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise RuntimeError("Brak docker compose – zainstaluj Docker Desktop / docker-compose-plugin")


def pause() -> None:
    if sys.stdin.isatty():
        Prompt.ask("\nEnter, aby wrócić", default="")


def clean_shared() -> None:
    DATA.mkdir(exist_ok=True)
    failed = False
    for p in list(DATA.iterdir()):
        try:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
        except OSError:
            failed = True
    if failed:  # pliki utworzone przez roota w kontenerze (Linux)
        run(["docker", "run", "--rm", "-v", f"{DATA}:/d", "alpine", "sh", "-c", "rm -rf /d/* /d/.[!.]* 2>/dev/null || true"])


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def load_api() -> List[Dict[str, Any]]:
    return load_exchanges(str(EXCHANGES))


def model_from_traffic() -> Optional[ApiModel]:
    ex = load_api()
    return ApiModel(ex, read_json(DATA / "static_api_hints.json", [])) if ex else None


# ----------------------------------------------------------------------------- UI
def banner() -> None:
    console.print(Panel.fit("[bold cyan]eBPF + LLM BLACKBOX API SYNTHESIZER[/bold cyan]\n[dim]PJATK MSc Research Console | "
                            f"Target {ORIG_URL} | Twin {TWIN_URL} | {MODEL_NAME}[/dim]", border_style="bright_blue", box=box.DOUBLE))


def status_bar() -> None:
    res = run(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"])
    t = Table(box=box.SIMPLE, header_style="bold magenta")
    t.add_column("Kontener", style="cyan")
    t.add_column("Status", style="green")
    rows = [l.split("\t") for l in (res.stdout or "").strip().splitlines() if "\t" in l]
    for r in rows or [["(brak)", "[red]OFFLINE[/red]"]]:
        t.add_row(*r[:2])
    console.print(t)
    ex = list(load_api()) if EXCHANGES.exists() else []
    stats = read_json(DATA / "collector_stats.json", {}) or {}
    k = stats.get("kernel", {})
    console.print(f" Wymiany API: [bold yellow]{len(ex)}[/bold yellow] | eBPF events: {k.get('events', 0)} dropped: [red]{k.get('dropped', 0)}[/red] "
                  f"| Twin: {'[bold green]GOTOWY[/bold green]' if (TWIN_DIR / 'main.py').exists() else '[yellow]BRAK[/yellow]'}\n")


# ----------------------------------------------------------------------------- doctor
def action_doctor() -> None:
    t = Table(title="Diagnostyka środowiska", box=box.ROUNDED)
    t.add_column("Sprawdzenie")
    t.add_column("Wynik")
    t.add_column("Uwagi", style="dim")
    def row(name: str, ok: bool, note: str = "") -> None:
        t.add_row(name, "[green]OK[/green]" if ok else "[red]FAIL[/red]", note)
    row("System", True, f"{platform.system()} {platform.release()} py{platform.python_version()}")
    row("docker", shutil.which("docker") is not None)
    d = run(["docker", "info", "--format", "{{.ServerVersion}} / {{.OperatingSystem}}"], timeout=20)
    row("docker daemon", d.returncode == 0, (d.stdout or d.stderr).strip()[:80])
    try:
        row("docker compose", True, " ".join(compose_cmd()))
    except RuntimeError as e:
        row("docker compose", False, str(e))
    b = run(["docker", "run", "--rm", "--privileged", "alpine", "ls", "/sys/kernel/btf/vmlinux"], timeout=120)
    row("BTF jądra (eBPF CO-RE)", b.returncode == 0, "wymagane przez bpftool btf dump" if b.returncode else "")
    try:
        models = OllamaClient(url=OLLAMA_URL, model=MODEL_NAME).list_models()
        row("Ollama", True, f"{len(models)} modeli")
        row(f"model {MODEL_NAME}", any(m.startswith(MODEL_NAME.split(":")[0]) for m in models), f"ollama pull {MODEL_NAME}")
    except LLMError as e:
        row("Ollama", False, str(e)[:90])
    try:
        DATA.mkdir(exist_ok=True)
        (DATA / ".w").write_text("x")
        (DATA / ".w").unlink()
        row("shared_data zapisywalny", True)
    except OSError as e:
        row("shared_data zapisywalny", False, str(e))
    console.print(t)


# ----------------------------------------------------------------------------- pipeline
def action_run_pipeline() -> None:
    dc = compose_cmd()
    console.print("[bold yellow][*] Reset stanu i start pipeline…[/bold yellow]")
    run(["docker", "rm", "-f", "digital_twin"])
    run(dc + ["down", "--remove-orphans"])
    clean_shared()
    up = run(dc + ["up", "-d", "--build"], capture=False)
    if up.returncode != 0:
        console.print("[red]docker compose up nie powiodło się[/red]")
        return
    console.print("[green][+] Kontenery działają. Logi na żywo (Ctrl+C = wróć do menu, pipeline działa dalej)[/green]\n")
    proc = subprocess.Popen(dc + ["logs", "-f", "--no-color", "ebpf_sniffer", "explorer", "synthesizer"], cwd=ROOT)
    try:
        while proc.poll() is None:
            if (DATA / "synthesizer_done.flag").exists() or (DATA / "synthesizer_failed.flag").exists():
                time.sleep(2)
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
    if (DATA / "synthesizer_failed.flag").exists():
        console.print("[red]Synthesizer zakończył się błędem – zobacz logi powyżej.[/red]")
    rep = read_json(DATA / "synthesis_report.json")
    if rep:
        console.print(f"[bold green]Gotowe[/bold green] – wynik offline: {rep.get('best_lenient_pct')}% | czas {rep.get('seconds')}s")


def action_inspect_traffic() -> None:
    if not EXCHANGES.exists():
        console.print("[red]Brak exchanges.jsonl – uruchom pipeline.[/red]")
        return pause()
    rows = [json.loads(l) for l in EXCHANGES.read_text(encoding="utf-8").splitlines() if l.strip()]
    t = Table(title=f"Przechwycone wymiany HTTP (eBPF TC) – {len(rows)}", box=box.ROUNDED)
    for c in ("#", "kind", "metoda", "ścieżka", "status", "ms", "body"):
        t.add_column(c)
    for r in rows[-80:]:
        resp = r.get("response") or {}
        body = (resp.get("body_text") or "")[:50].replace("\n", " ")
        lat = f"{(r.get('latency_us') or 0) / 1000:.1f}"
        t.add_row(str(r["id"]), r["kind"], r["request"]["method"], r["request"]["path"][:55], str(resp.get("status", "-")), lat, body)
    console.print(t)
    pause()


def action_inspect_twin() -> None:
    if not (TWIN_DIR / "main.py").exists():
        console.print("[red]Bliźniak nie został wygenerowany.[/red]")
        return pause()
    for name, lang, title in (("openapi.json", "json", "OpenAPI 3.1 (deterministyczne z ruchu)"), ("schema.sql", "sql", "Schemat SQL"), ("headers.json", "json", "Nagłówki/walidacja"), ("main.py", "python", "Digital Twin main.py")):
        p = TWIN_DIR / name
        if p.exists():
            console.print(Panel(Syntax(p.read_text(encoding="utf-8")[:12000], lang, theme="monokai", line_numbers=True), title=title))
    pause()


# ----------------------------------------------------------------------------- twin
def rebuild_and_start_twin() -> Tuple[bool, str]:
    run(["docker", "rm", "-f", "digital_twin"])
    b = run(["docker", "build", "-t", "api-digital-twin", str(TWIN_DIR)], timeout=600)
    if b.returncode != 0:
        return False, ((b.stderr or "") + (b.stdout or ""))[-800:]
    r = run(["docker", "run", "-d", "--name", "digital_twin", "-p", "8081:8000", "api-digital-twin"])
    if r.returncode != 0:
        return False, (r.stderr or r.stdout)[-500:]
    for _ in range(30):
        time.sleep(1)
        st = run(["docker", "inspect", "-f", "{{.State.Running}}", "digital_twin"]).stdout.strip()
        if st != "true":
            break
        try:
            requests.get(TWIN_URL + "/__probe__", timeout=1.5)
            return True, ""
        except requests.RequestException:
            continue
    st = run(["docker", "inspect", "-f", "{{.State.Running}}", "digital_twin"]).stdout.strip()
    if st == "true":
        return True, ""
    logs = run(["docker", "logs", "--tail", "40", "digital_twin"])
    return False, "\n".join(((logs.stdout or "") + (logs.stderr or "")).strip().splitlines()[-25:])


def action_deploy_twin() -> None:
    if not (TWIN_DIR / "Dockerfile").exists():
        console.print("[red]Brak plików w shared_data/generated_twin/[/red]")
        return pause()
    with console.status("Buduję i uruchamiam bliźniaka…"):
        ok, err = rebuild_and_start_twin()
    console.print(f"[bold green][+] Twin działa: {TWIN_URL}[/bold green]" if ok else f"[red][!] Błąd:\n{err}[/red]")
    pause()


# ----------------------------------------------------------------------------- differential testing
def build_cases(ex: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cases = diffing.cases_from_exchanges(ex, 250)
    cases += diffing.derive_probe_cases(ex, 60)
    if DIFF_SAFE:
        cases = [c for c in cases if c["method"] in ("GET", "HEAD", "OPTIONS", "POST")]
    return cases


def send(sess: requests.Session, base: str, c: Dict[str, Any]) -> Dict[str, Any]:
    try:
        kw: Dict[str, Any] = {"headers": c.get("headers") or {}, "timeout": REQ_TIMEOUT, "allow_redirects": False}
        if c.get("payload") is not None:
            kw["json"] = c["payload"]
        elif c.get("raw"):
            kw["data"] = c["raw"]
        return diffing.resp_from_requests(sess.request(c["method"], base + c["path"], **kw))
    except requests.RequestException as e:
        return diffing.make_resp("CONN_ERR", {}, str(e))


def run_differential(show: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    ex = load_api()
    cases = build_cases(ex)
    so, st = requests.Session(), requests.Session()
    out = []
    for c in cases:
        orig, twin = send(so, ORIG_URL, c), send(st, TWIN_URL, c)
        issues = diffing.compare(orig, twin)
        d = dict(c)
        d.update(expected=orig, actual=twin, issues=[i.as_dict() for i in issues])
        out.append(d)
    sc = diffing.score(out)
    if show:
        t = Table(title="Raport zgodności behawioralnej (differential testing)", box=box.DOUBLE_EDGE)
        for col in ("Źródło", "Żądanie", "Orig", "Twin", "Wynik"):
            t.add_column(col)
        bad = [c for c in out if c["issues"]]
        for c in (bad + [c for c in out if not c["issues"]][:10])[:45]:
            major = any(i["severity"] == "major" for i in c["issues"])
            verdict = "[red]DIFF[/red]" if major else ("[yellow]minor[/yellow]" if c["issues"] else "[green]MATCH[/green]")
            kinds = ",".join(sorted({i["kind"] for i in c["issues"]}))[:40]
            t.add_row(c["source"][:14], f"{c['method']} {c['path']}"[:58], str(c["expected"]["status"]), str(c["actual"]["status"]), f"{verdict} {kinds}")
        console.print(t)
        console.print(f"\n[bold]Zgodność:[/bold] lenient {sc['lenient_match']}/{sc['cases']} ([cyan]{sc['lenient_pct']}%[/cyan]) | strict {sc['strict_pct']}% | {sc['issue_kinds']}")
    (DATA / "diff_report.json").write_text(json.dumps({"score": sc, "cases": [
        {k: v for k, v in c.items() if k in ("method", "path", "source", "issues")} for c in out]}, ensure_ascii=False, indent=1), encoding="utf-8")
    return out, sc


def action_differential() -> None:
    if not EXCHANGES.exists():
        console.print("[red]Brak ruchu – uruchom pipeline.[/red]")
        return pause()
    if DIFF_SAFE is False:
        console.print("[dim]Uwaga: testy wysyłają też POST/PUT/PATCH/DELETE do oryginału (DIFF_SAFE=1 to wyłącza).[/dim]")
    cases, sc = run_differential()
    if sc["lenient_pct"] < 100 and Confirm.ask("Uruchomić pętlę CEGIS?", default=True):
        cegis(cases)
    pause()


# ----------------------------------------------------------------------------- CEGIS
def cegis(cases: Optional[List[Dict[str, Any]]] = None) -> None:
    py = TWIN_DIR / "main.py"
    if not py.exists():
        console.print("[red]Brak main.py[/red]")
        return
    model = model_from_traffic()
    ddl = (TWIN_DIR / "schema.sql").read_text(encoding="utf-8") if (TWIN_DIR / "schema.sql").exists() else ""
    digest = model.digest(6000) if model else ""
    tables = [r.name for r in model.resources.values()] if model else []
    llm = OllamaClient(url=OLLAMA_URL, model=MODEL_NAME, logger=log)
    try:
        llm.ensure_ready()
    except LLMError as e:
        console.print(f"[red]{e}[/red]")
        return
    if cases is None:
        cases, _ = run_differential(show=False)
    sc = diffing.score(cases)
    best = {"pct": sc["lenient_pct"], "code": py.read_text(encoding="utf-8")}
    history = [{"iter": 0, "score": sc}]
    stagn = 0
    regress = ""
    for it in range(1, MAX_CEGIS + 1):
        if best["pct"] >= 100:
            break
        logs = run(["docker", "logs", "--tail", "80", "digital_twin"])
        runtime_logs = ((logs.stdout or "") + "\n" + (logs.stderr or "")).strip()[-2500:]
        analysis = diffing.analyze_cases(cases, runtime_logs, tables)
        console.print(f"\n[bold yellow][*] CEGIS {it}/{MAX_CEGIS}: {sc['lenient_pct']}% | {analysis['counts']}[/bold yellow]")
        for h in analysis["hints"][:6]:
            console.print(f"   [dim]• {h[:150]}[/dim]")
        prompt = repair.repair_prompt(best["code"], ddl, diffing.render_analysis(analysis), runtime_logs, digest, llm.prompt_budget_tokens, "", regress)
        try:
            new = llm.generate_tagged(prompt, "python", system=repair.SYSTEM, label=f"cegis#{it}")
        except LLMError as e:
            console.print(f"[red]LLM: {e}[/red]")
            break
        new, notes = codecheck.autofix(new)
        problems = codecheck.lint(new)
        try:
            ast.parse(new)
        except SyntaxError as e:
            console.print(f"[red]SyntaxError linia {e.lineno} – pomijam iterację[/red]")
            regress = f"Previous output had SyntaxError at line {e.lineno}: {e.msg}. Return the full file."
            continue
        if problems:
            console.print(f"[yellow]lint: {problems[:3]}[/yellow]")
        py.write_text(new, encoding="utf-8")
        with console.status("Przebudowa bliźniaka…"):
            ok, err = rebuild_and_start_twin()
        if not ok:
            console.print(f"[red]Kontener nie wstał:\n{err}[/red]")
            regress = f"The previous version crashed at startup:\n{err}"
            py.write_text(best["code"], encoding="utf-8")
            continue
        cases, _ = run_differential(show=False)
        sc = diffing.score(cases)
        history.append({"iter": it, "score": sc, "autofix": notes, "lint": problems})
        console.print(f"   -> [cyan]{sc['lenient_pct']}%[/cyan] (najlepszy dotąd {best['pct']}%)")
        if sc["lenient_pct"] > best["pct"]:
            best, stagn, regress = {"pct": sc["lenient_pct"], "code": new}, 0, ""
        else:
            stagn += 1
            broken = [f"{c['method']} {c['path']}" for c in cases if any(i["severity"] == "major" for i in c["issues"])][:8]
            regress = f"Last attempt did not improve ({sc['lenient_pct']}% vs {best['pct']}%). Still failing: {broken}"
            py.write_text(best["code"], encoding="utf-8")
            with console.status("Rollback do najlepszej wersji…"):
                rebuild_and_start_twin()
            cases, _ = run_differential(show=False)
            if stagn >= 2:
                console.print("[yellow]Stagnacja – kończę.[/yellow]")
                break
    (DATA / "cegis_history.json").write_text(json.dumps({"best_pct": best["pct"], "history": history}, indent=1, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n[bold green]CEGIS zakończony. Najlepszy wynik: {best['pct']}%[/bold green]")
    run_differential(show=True)


def action_cegis() -> None:
    cegis()
    pause()


# ----------------------------------------------------------------------------- benchmark
def bench_url(url: str, n: int, workers: int) -> Dict[str, Any]:
    lat: List[float] = []
    err = 0

    def one(_: int) -> Optional[float]:
        try:
            t = time.perf_counter()
            requests.get(url, timeout=REQ_TIMEOUT)
            return (time.perf_counter() - t) * 1000
        except requests.RequestException:
            return None

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, range(n)):
            lat.append(r) if r is not None else None
            err += r is None
    dur = time.perf_counter() - t0
    lat.sort()
    return {"n": n, "errors": err, "rps": round(n / dur, 1), "p50": round(statistics.median(lat), 1) if lat else None,
            "p95": round(lat[int(len(lat) * 0.95) - 1], 1) if len(lat) > 20 else None, "mean": round(statistics.mean(lat), 1) if lat else None}


def docker_stats(names: List[str]) -> Dict[str, str]:
    r = run(["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"] + names, timeout=30)
    return {l.split("|")[0]: f"CPU {l.split('|')[1]}, MEM {l.split('|')[2]}" for l in (r.stdout or "").splitlines() if "|" in l}


def action_bench() -> None:
    ex = load_api()
    gets = sorted({e["request"]["path"] for e in ex if e["request"]["method"] == "GET" and "{" not in e["endpoint"] and e["response"]["status"] == 200})[:8]
    n, workers = int(os.getenv("BENCH_N", "200")), int(os.getenv("BENCH_WORKERS", "8"))
    t = Table(title=f"Benchmark ({n} żądań, {workers} wątków)", box=box.ROUNDED)
    for c in ("Endpoint", "Orig rps", "Twin rps", "Orig p50/p95 ms", "Twin p50/p95 ms", "Err o/t"):
        t.add_column(c)
    results = {}
    for path in gets:
        o, w = bench_url(ORIG_URL + path, n, workers), bench_url(TWIN_URL + path, n, workers)
        results[path] = {"orig": o, "twin": w}
        t.add_row(path[:45], str(o["rps"]), str(w["rps"]), f"{o['p50']}/{o['p95']}", f"{w['p50']}/{w['p95']}", f"{o['errors']}/{w['errors']}")
    console.print(t)
    st = docker_stats(["target_app", "digital_twin"])
    sizes = {}
    for label, img in (("orig", "bkimminich/juice-shop:latest"), ("twin", "api-digital-twin")):
        r = run(["docker", "image", "inspect", img, "--format", "{{.Size}}"])
        sizes[label] = int(r.stdout.strip()) // (1 << 20) if r.stdout.strip().isdigit() else None
    console.print(f"Zasoby: {st} | rozmiar obrazu [MB]: {sizes}")
    (DATA / "bench_report.json").write_text(json.dumps({"endpoints": results, "docker_stats": st, "image_mb": sizes}, indent=1), encoding="utf-8")
    pause()


# ----------------------------------------------------------------------------- raport
def action_report() -> None:
    parts = {n: read_json(DATA / f) for n, f in (("collector", "collector_stats.json"), ("explorer", "explorer_report.json"),
                                                 ("synthesis", "synthesis_report.json"), ("diff", "diff_report.json"),
                                                 ("cegis", "cegis_history.json"), ("bench", "bench_report.json"))}
    md = ["# Raport eksperymentu\n"]
    c = parts["collector"] or {}
    md.append(f"## Przechwytywanie (eBPF)\n- kernel: {c.get('kernel')}\n- przepływy: {c.get('flows')}\n- wymiany API: {c.get('exchanges_api')}, statyczne: {c.get('exchanges_static')}\n")
    e = parts["explorer"] or {}
    md.append(f"## Eksploracja\n- statystyki: {e.get('stats')}\n- profile: {e.get('profiles')}\n- czas: {e.get('seconds')}s\n- endpointy: {len(e.get('endpoints_seen', {}))}\n")
    s = parts["synthesis"] or {}
    md.append(f"## Synteza\n- model: {s.get('model')}, IR: {s.get('ir')}\n- najlepszy wynik offline: {s.get('best_lenient_pct')}%\n- czas: {s.get('seconds')}s\n")
    d = parts["diff"] or {}
    md.append(f"## Zgodność behawioralna\n{json.dumps(d.get('score'), ensure_ascii=False)}\n")
    g = parts["cegis"] or {}
    md.append("## CEGIS\n" + "\n".join(f"- iter {h['iter']}: {h['score']['lenient_pct']}%" for h in g.get("history", [])) + "\n")
    md.append(f"## Wydajność\n```json\n{json.dumps(parts['bench'], indent=1)}\n```\n")
    out = DATA / "report.md"
    out.write_text("\n".join(md), encoding="utf-8")
    console.print(f"[green]Zapisano {out}[/green]")
    pause()


def action_curl() -> None:
    method = Prompt.ask("Metoda", choices=["GET", "POST", "PUT", "PATCH", "DELETE"], default="GET")
    path = Prompt.ask("Ścieżka", default="/")
    body = None
    if method in ("POST", "PUT", "PATCH"):
        raw = Prompt.ask("JSON body", default="{}")
        try:
            body = json.loads(raw) if raw.strip() else None
        except ValueError as e:
            console.print(f"[red]Niepoprawny JSON: {e}[/red]")
            return pause()
    for label, base in (("TWIN", TWIN_URL), ("ORIG", ORIG_URL)):
        try:
            r = requests.request(method, base + path, json=body, timeout=REQ_TIMEOUT)
            console.print(f"[bold]{label}[/bold] HTTP {r.status_code}")
            try:
                console.print(Syntax(json.dumps(r.json(), indent=2, ensure_ascii=False)[:2500], "json", theme="monokai"))
            except ValueError:
                console.print(r.text[:800])
        except requests.RequestException as e:
            console.print(f"[red]{label}: {e}[/red]")
    pause()


# ----------------------------------------------------------------------------- main
def menu() -> None:
    actions = {"1": action_run_pipeline, "2": action_inspect_traffic, "3": action_inspect_twin, "4": action_deploy_twin,
               "5": action_differential, "6": action_cegis, "7": action_bench, "8": action_report, "9": action_curl, "d": action_doctor}
    labels = ["Pipeline (Target → eBPF → Explorer → Synthesizer)", "Podgląd wymian HTTP (eBPF)", "Podgląd OpenAPI / SQL / main.py",
              "Zbuduj i uruchom Twin", "Differential test (+ CEGIS)", "Sama pętla CEGIS", "Benchmark wydajności", "Raport (report.md)", "Ręczne zapytanie (twin vs orig)"]
    while True:
        console.clear()
        banner()
        try:
            status_bar()
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]status: {e}[/red]")
        for i, l in enumerate(labels, 1):
            console.print(f"  [cyan][{i}][/cyan] {l}")
        console.print("  [cyan][d][/cyan] Doctor (diagnostyka)   [cyan][0][/cyan] Wyjście\n")
        ch = Prompt.ask("Opcja", choices=list(actions) + ["0"], default="1")
        if ch == "0":
            return
        try:
            actions[ch]()
        except KeyboardInterrupt:
            continue
        except Exception as e:  # noqa: BLE001
            console.print_exception()
            console.print(f"[red]Błąd akcji: {e}[/red]")
            pause()


def main() -> None:
    ap = argparse.ArgumentParser(description="apiminer research console")
    ap.add_argument("cmd", nargs="?", default="menu", choices=["menu", "run", "deploy", "test", "cegis", "bench", "report", "doctor"])
    a = ap.parse_args()
    {"menu": menu, "run": action_run_pipeline, "deploy": action_deploy_twin, "test": lambda: run_differential(True),
     "cegis": lambda: cegis(), "bench": action_bench, "report": action_report, "doctor": action_doctor}[a.cmd]()


if __name__ == "__main__":
    main()
