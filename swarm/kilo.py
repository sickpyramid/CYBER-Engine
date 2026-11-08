"""KiloCode OpenAI-compatible client — async, rate-limited, reasoning-aware.

Handles the two quirks we verified live:
  1. reflection/* models put their output in `reasoning`/`reasoning_details` and only emit
     `content` once they finish thinking — so we budget tokens and fall back to reasoning text.
  2. free models rate-limit, so we throttle (min interval) and retry on 429/5xx with backoff.
"""
from __future__ import annotations
import asyncio, time, json
import httpx
from . import config

_last_call = 0.0
_lock = asyncio.Lock()
_calls_today = 0
_day = time.strftime("%Y-%m-%d")


class RateLimited(Exception): ...
class DailyCapReached(Exception): ...


def _reset_day_if_needed():
    global _calls_today, _day
    d = time.strftime("%Y-%m-%d")
    if d != _day:
        _day, _calls_today = d, 0


async def chat(messages: list[dict], model: str, *, max_tokens: int | None = None,
               temperature: float = 0.7, timeout: float = 180.0) -> dict:
    """One chat completion. Returns {content, reasoning, usage, model, raw}."""
    global _last_call, _calls_today
    lim = config.LIMITS
    max_tokens = max_tokens or lim.max_tokens

    async with _lock:
        _reset_day_if_needed()
        if lim.max_calls_per_day and _calls_today >= lim.max_calls_per_day:
            raise DailyCapReached(f"daily cap {lim.max_calls_per_day} reached")
        wait = lim.min_call_interval - (time.time() - _last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_call = time.time()
        _calls_today += 1

    payload = {"model": model, "messages": messages, "max_tokens": max_tokens,
               "temperature": temperature}
    headers = {"Authorization": f"Bearer {config.KILO_TOKEN}", "Content-Type": "application/json"}
    url = f"{config.KILO_BASE}/chat/completions"

    last_err = None
    for attempt in range(lim.max_retries):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                r = await c.post(url, headers=headers, json=payload)
            if r.status_code == 429:
                raise RateLimited("429")
            if r.status_code >= 500:
                raise RateLimited(f"{r.status_code}")
            r.raise_for_status()
            d = r.json()
            choice = (d.get("choices") or [{}])[0]
            msg = choice.get("message", {}) or {}
            content = (msg.get("content") or "").strip()
            reasoning = msg.get("reasoning") or ""
            if not reasoning and msg.get("reasoning_details"):
                reasoning = " ".join(x.get("text", "") for x in msg["reasoning_details"])
            # reflection models: if content is empty but reasoning has the answer, use it
            if not content and reasoning:
                content = reasoning.strip()
            return {"content": content, "reasoning": reasoning,
                    "usage": d.get("usage", {}), "model": d.get("model", model),
                    "finish": choice.get("finish_reason"), "raw": d}
        except (RateLimited, httpx.HTTPError) as e:
            last_err = e
            await asyncio.sleep(min(2 ** attempt * 2, 30))
    raise RuntimeError(f"kilo chat failed after {lim.max_retries} tries: {last_err}")


def calls_today() -> int:
    return _calls_today
