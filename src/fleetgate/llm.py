"""LLM protocol and implementations. Everything in tests and evals uses `ScriptedLLM`; no network."""
from __future__ import annotations

import os
from typing import Protocol


class LLM(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class AnthropicLLM:
    def __init__(self, model: str | None = None, max_tokens: int = 700):
        import anthropic  # optional: pip install fleetgate[llm]

        self.client = anthropic.Anthropic()
        self.model = model or os.environ.get("FLEETGATE_MODEL", "claude-sonnet-5-5")
        self.max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        r = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in r.content if b.type == "text")


class ScriptedLLM:
    """Replays canned replies in order; repeats the last one once the script runs out."""

    def __init__(self, replies: list[str]):
        if not replies:
            raise ValueError("ScriptedLLM needs at least one reply")
        self.replies, self.calls = list(replies), []
        self._i = 0

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        reply = self.replies[min(self._i, len(self.replies) - 1)]
        self._i += 1
        return reply


class FailingLLM:
    """Raises on every call (simulates an outage) so callers must degrade gracefully."""

    def __init__(self, exc: type[Exception] = RuntimeError):
        self.exc, self.calls = exc, 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        raise self.exc("llm unavailable")


def safe_complete(llm: LLM | None, system: str, user: str, fallback: str) -> str:
    """Call the model if there is one; on any failure or empty reply return the fallback."""
    if llm is None:
        return fallback
    try:
        out = llm.complete(system, user)
    except Exception:
        return fallback
    out = (out or "").strip()
    return out or fallback
