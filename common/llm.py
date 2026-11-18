"""Klient Ollamy: streaming /api/chat, idle-timeout (a nie całkowity), retry z backoffem, wykrywanie ucięcia, kontynuacje."""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from .logs import get_logger


class LLMError(RuntimeError):
    pass


@dataclass
class GenResult:
    text: str
    tokens: int
    seconds: float
    truncated: bool
    model: str


def est_tokens(s: str) -> int:
    return int(len(s) / 3.2) + 1


def extract_tag(text: str, tag: str) -> str:
    """Wyciąga treść <tag>…</tag>; toleruje brak zamknięcia, ``` fences i wielokrotne wystąpienia (bierze najdłuższe)."""
    matches = re.findall(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
    if matches:
        content = max(matches, key=len)
    else:
        m = re.search(rf"<{tag}>(.*)$", text, re.DOTALL)
        content = m.group(1) if m else text
    content = content.strip()
    fence = re.match(r"^```[a-zA-Z0-9_+-]*\n(.*?)(?:\n```.*)?$", content, re.DOTALL)
    if fence:
        content = fence.group(1)
    return content.strip()


class OllamaClient:
    def __init__(self, url: Optional[str] = None, model: Optional[str] = None, num_ctx: Optional[int] = None,
                 num_predict: Optional[int] = None, temperature: float = 0.1, retries: int = 3, logger=None):
        self.url = (url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("MODEL_NAME", "qwen2.5-coder:14b")
        self.num_ctx = num_ctx or int(os.getenv("OLLAMA_NUM_CTX", "16384"))
        self.num_predict = num_predict or int(os.getenv("OLLAMA_NUM_PREDICT", "6144"))
        self.temperature = temperature
        self.retries = retries
        self.connect_timeout = float(os.getenv("OLLAMA_CONNECT_TIMEOUT", "10"))
        self.idle_timeout = float(os.getenv("OLLAMA_IDLE_TIMEOUT", "300"))  # pierwszy token po załadowaniu modelu bywa wolny
        self.keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "30m")
        self.log = logger or get_logger("llm")

    @property
    def prompt_budget_tokens(self) -> int:
        return max(1024, self.num_ctx - self.num_predict - 256)

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=(self.connect_timeout, 15))
            r.raise_for_status()
        except requests.RequestException as e:
            raise LLMError(
                f"Ollama niedostępna pod {self.url} ({type(e).__name__}). Sprawdź: `ollama serve`, OLLAMA_URL "
                f"(w Dockerze: http://host.docker.internal:11434; na Linuksie wymaga extra_hosts host-gateway)."
            ) from e
        return [m.get("name", "") for m in r.json().get("models", [])]

    def ensure_ready(self) -> None:
        models = self.list_models()
        if not any(m == self.model or m.split(":")[0] == self.model.split(":")[0] and ":" not in self.model for m in models):
            raise LLMError(f"Model '{self.model}' nie jest pobrany. Uruchom: ollama pull {self.model}  (dostępne: {models})")

    def chat(self, messages: List[Dict[str, str]], *, num_predict: Optional[int] = None, json_mode: bool = False,
             label: str = "LLM", temperature: Optional[float] = None) -> GenResult:
        prompt_tokens = est_tokens(" ".join(m["content"] for m in messages))
        if prompt_tokens > self.prompt_budget_tokens:
            self.log.warning("[%s] Prompt ~%d tok > budżet %d tok (num_ctx=%d - num_predict=%d): Ollama po cichu utnie początek promptu!",
                             label, prompt_tokens, self.prompt_budget_tokens, self.num_ctx, self.num_predict)
        payload: Dict[str, Any] = {
            "model": self.model, "messages": messages, "stream": True, "keep_alive": self.keep_alive,
            "options": {"temperature": self.temperature if temperature is None else temperature,
                        "num_ctx": self.num_ctx, "num_predict": num_predict or self.num_predict},
        }
        if json_mode:
            payload["format"] = "json"
        last_err: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                return self._stream(payload, label)
            except LLMError:
                raise
            except (requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError) as e:
                last_err = e
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code < 500:
                    raise LLMError(f"HTTP {e.response.status_code}: {e.response.text[:200]}") from e
                last_err = e
            wait = 2 ** attempt
            self.log.warning("[%s] Próba %d/%d nieudana (%s: %s) – ponawiam za %ds", label, attempt, self.retries, type(last_err).__name__, str(last_err)[:120], wait)
            time.sleep(wait)
        raise LLMError(f"[{label}] Wyczerpano {self.retries} prób: {last_err}")

    def _stream(self, payload: Dict[str, Any], label: str) -> GenResult:
        chunks: List[str] = []
        tokens, done_reason, t0 = 0, None, time.time()
        next_log = 400
        with requests.post(f"{self.url}/api/chat", json=payload, stream=True, timeout=(self.connect_timeout, self.idle_timeout)) as resp:
            if resp.status_code == 404:
                raise LLMError(f"Model '{self.model}' nie istnieje w Ollamie (ollama pull {self.model}).")
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                data = json.loads(line.decode("utf-8"))
                if "error" in data:
                    raise LLMError(f"Ollama: {data['error']}")
                piece = (data.get("message") or {}).get("content", "")
                if piece:
                    chunks.append(piece)
                    tokens += 1
                    if tokens >= next_log:
                        self.log.info("[%s] …%d tokenów (%.1f tok/s)", label, tokens, tokens / max(0.1, time.time() - t0))
                        next_log += 400
                if data.get("done"):
                    done_reason = data.get("done_reason")
                    break
        secs = time.time() - t0
        self.log.info("[%s] gotowe: %d tokenów w %.0fs (%s)", label, tokens, secs, done_reason or "?")
        return GenResult("".join(chunks), tokens, secs, done_reason == "length", self.model)

    def generate_tagged(self, prompt: str, tag: str, system: Optional[str] = None, label: str = "LLM",
                        max_continuations: int = 2, json_mode: bool = False) -> str:
        msgs: List[Dict[str, str]] = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        res = self.chat(msgs, label=label, json_mode=json_mode)
        text = res.text
        n = 0
        while res.truncated and f"</{tag}>" not in text and n < max_continuations:
            n += 1
            self.log.warning("[%s] Odpowiedź ucięta (num_predict) – kontynuacja %d/%d", label, n, max_continuations)
            msgs = msgs + [{"role": "assistant", "content": text},
                           {"role": "user", "content": f"Continue EXACTLY where you stopped. Do not repeat anything. Finish with </{tag}>."}]
            res = self.chat(msgs, label=f"{label}+{n}")
            text += res.text
        return extract_tag(text, tag)
