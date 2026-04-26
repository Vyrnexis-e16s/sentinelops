"""OpenAI-compatible chat completion for VAPT triage (optional — requires API key)."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

MAX_OUT_TOKENS = 4096


class LlmNotConfiguredError(RuntimeError):
    pass


class LlmUpstreamError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


async def summarize_triage(
    *, context: str, instruction: str, inject_mitre_context: bool = False
) -> tuple[str, str]:
    if not (settings.openai_api_key or "").strip():
        raise LlmNotConfiguredError(
            "No LLM API key configured. Set OPENAI_API_KEY (or use an OpenAI-compatible "
            "endpoint with SENTINELOPS_LLM_BASE_URL) on the API server."
        )
    model = (settings.sentinelops_llm_model or "gpt-4o-mini").strip()
    base = (settings.sentinelops_llm_base_url or "https://api.openai.com/v1").rstrip("/")
    url = f"{base}/chat/completions"
    key = (settings.openai_api_key or "").strip()

    sys_content = instruction
    if inject_mitre_context:
        from app.modules.vapt.mitre_data import mitre_addendum_for_prompt

        addendum = mitre_addendum_for_prompt(max_lines=50)
        sys_content = (
            f"{instruction}\n\n---\nCurated MITRE ATT&CK technique reference (subset; align mentions to these when applicable):\n"
            f"{addendum}"
        )

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": sys_content},
            {
                "role": "user",
                "content": f"Data and findings from our security platform (JSON and text below):\n\n{context[:190_000]}",
            },
        ],
        "max_tokens": MAX_OUT_TOKENS,
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
        r = await client.post(url, json=body, headers=headers)
    if r.status_code >= 400:
        log.warning("vapt.llm.error", status=r.status_code, body=r.text[:500])
        raise LlmUpstreamError(
            f"LLM provider returned {r.status_code}. Check key, model name, and base URL.",
            status_code=r.status_code,
        )
    data = r.json()
    try:
        text = (data["choices"][0]["message"].get("content") or "").strip()
    except (KeyError, IndexError, TypeError) as exc:
        log.warning("vapt.llm.parse", error=str(exc))
        raise LlmUpstreamError("Unexpected LLM response shape", status_code=r.status_code) from exc
    if not text:
        raise LlmUpstreamError("Empty summary from model", status_code=200)
    return text, model
