# apiminer v2 – autonomiczna synteza Digital Twin (eBPF + Playwright + LLM + CEGIS)

## Uruchomienie
```
pip install rich requests
ollama pull qwen2.5-coder:14b      # na hoście
python synthctl.py doctor          # diagnostyka (docker, BTF, ollama)
python synthctl.py                 # menu:  1 = pipeline,  5 = differential + CEGIS,  7 = benchmark,  8 = raport
```
Auth (opcjonalnie): odkomentuj zmienne `AUTH_*` / `PROFILES` w `docker-compose.yml` (explorer).
Testy offline parsera: `python -m pytest tests/`.

## Przepływ danych (`shared_data/`)
`sniffer_ready.flag` → explorer → `playwright_calls.jsonl`, `explorer_report.json`, `static_api_hints.json`, `*.har`
→ kolektor: `exchanges.jsonl`, `collector_stats.json`, `collector_done.flag`
→ synthesizer: `generated_twin/` (+ `ir_digest.txt`, `seed.json`, `headers.json`), `synthesis_report.json`
→ synthctl: `diff_report.json`, `cegis_history.json`, `bench_report.json`, `report.md`

## Architektura
- `common/httpwire.py` – reasemblacja TCP (seq, SYN/ISN, luki) + parser HTTP/1.x (chunked, gzip/deflate/br, pipelining).
- `common/ir.py` – deterministyczny kontrakt: JSON Schema, zasoby, FK, DDL, OpenAPI 3.1, seedy, nagłówki, auth.
- `common/diffing.py` – porównanie odpowiedzi + analiza semantyczna (FK, trasy zagnieżdżone, statusy, tracebacki).
- `common/repair.py`, `common/llm.py` – prompty + klient Ollamy (streaming, idle-timeout, retry, kontynuacje).
- `common/twin_runtime.py` – deterministyczny runtime bliźniaka (DB, seed, nagłówki); LLM pisze tylko `main.py`.
