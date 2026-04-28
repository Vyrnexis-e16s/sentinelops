"""OpenAI-compatible chat for VAPT triage: single model or two-step (draft + refine) cascade."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

MAX_OUT_TOKENS = 4096
MAX_DRAFT_TOKENS = 2_048

DRAFT_SYSTEM = (
    "You are a security analyst. Read the platform telemetry and findings below. "
    "Output a **structured draft only** with these exact sections (markdown headings):\n"
    "## Facts\n## Notable risks\n## Gaps or uncertainty\n## Suggested follow-ups\n"
    "Be concise and factual. Do not write an executive summary — that is a later step."
)


class LlmNotConfiguredError(RuntimeError):
    pass


class LlmUpstreamError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _effective_api_key() -> str:
    raw = (settings.openai_api_key or "").strip()
    if raw:
        return raw
    if settings.sentinelops_llm_ollama:
        return "ollama"
    return ""


def llm_is_configured() -> bool:
    """True when we can call the provider (OpenAI key or Ollama mode)."""
    if _effective_api_key():
        return True
    return False


def _refine_model_name() -> str:
    return (settings.sentinelops_llm_model or "gpt-4o-mini").strip()


def _draft_model_name() -> str:
    return (settings.sentinelops_llm_draft_model or "").strip()


async def _chat(
    client: httpx.AsyncClient,
    *,
    model: str,
    system: str,
    user: str,
    api_key: str,
    base: str,
    max_tokens: int = MAX_OUT_TOKENS,
    temperature: float = 0.2,
) -> str:
    url = f"{base.rstrip('/')}/chat/completions"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        r = await client.post(url, json=body, headers=headers)
    except httpx.ConnectError as exc:
        log.warning("vapt.llm.connect_error", base=base, model=model, error=str(exc))
        raise LlmUpstreamError(
            f"Cannot reach LLM endpoint at {base} (connection refused / unreachable). "
            f"If using Ollama on the host with a Docker backend, bind Ollama to 0.0.0.0:11434 "
            f"(systemd: Environment=\"OLLAMA_HOST=0.0.0.0:11434\") and ensure SENTINELOPS_LLM_BASE_URL "
            f"is host.docker.internal or your host LAN IP.",
            status_code=502,
        ) from exc
    except httpx.TimeoutException as exc:
        log.warning("vapt.llm.timeout", base=base, model=model, error=str(exc))
        raise LlmUpstreamError(
            f"LLM endpoint at {base} timed out for model {model!r} after "
            f"{settings.sentinelops_llm_timeout_secs}s. On CPU-only Ollama, a 7B model often needs "
            f"4–6 minutes for the first response (cold load). Try one of: "
            f"(1) click 'Warm LLM' first; (2) use a smaller draft model "
            f"(e.g. SENTINELOPS_LLM_DRAFT_MODEL=qwen2.5:1.5b or phi3.5); "
            f"(3) raise SENTINELOPS_LLM_TIMEOUT_SECS; (4) disable cascade for this run.",
            status_code=504,
        ) from exc
    except httpx.RequestError as exc:
        log.warning("vapt.llm.request_error", base=base, model=model, error=str(exc))
        raise LlmUpstreamError(
            f"Network error talking to LLM endpoint at {base}: {exc}.",
            status_code=502,
        ) from exc
    if r.status_code >= 400:
        body_excerpt = r.text[:500]
        log.warning("vapt.llm.error", model=model, status=r.status_code, body=body_excerpt)
        # Ollama returns 404 with "model 'X' not found" if the model isn't pulled — bubble that up.
        hint = ""
        if r.status_code == 404 and ("not found" in body_excerpt.lower() or "no such model" in body_excerpt.lower()):
            hint = f" Pull it first on the host: 'ollama pull {model}'."
        raise LlmUpstreamError(
            f"LLM provider returned {r.status_code} for model {model!r}.{hint} "
            f"Check key, name, and base URL.",
            status_code=r.status_code,
        )
    try:
        data = r.json()
    except ValueError as exc:
        log.warning("vapt.llm.parse_json", model=model, error=str(exc), body=r.text[:200])
        raise LlmUpstreamError(
            f"LLM provider returned non-JSON response for model {model!r}.",
            status_code=502,
        ) from exc
    try:
        text = (data["choices"][0]["message"].get("content") or "").strip()
    except (KeyError, IndexError, TypeError) as exc:
        log.warning("vapt.llm.parse", model=model, error=str(exc))
        raise LlmUpstreamError("Unexpected LLM response shape", status_code=502) from exc
    if not text:
        raise LlmUpstreamError(
            f"Empty response from model {model!r} (the model returned 200 with no content; "
            f"this often means the model is still loading — try 'Warm LLM' once and retry).",
            status_code=502,
        )
    return text


async def summarize_triage(
    *,
    context: str,
    instruction: str,
    inject_mitre_context: bool = False,
    use_cascade: bool = True,
) -> tuple[str, str]:
    if not llm_is_configured():
        raise LlmNotConfiguredError(
            "No LLM configured. Set OPENAI_API_KEY, or for Ollama set SENTINELOPS_LLM_OLLAMA=1 "
            "and SENTINELOPS_LLM_BASE_URL (see scripts/setup-local-llm.sh)."
        )
    api_key = _effective_api_key()
    base = (settings.sentinelops_llm_base_url or "https://api.openai.com/v1").rstrip("/")
    refine = _refine_model_name()
    draft = _draft_model_name()
    want_cascade = (
        use_cascade
        and settings.sentinelops_llm_cascade
        and bool(draft)
        and draft != refine
    )

    sys_refine = instruction
    if inject_mitre_context:
        from app.modules.vapt.mitre_data import mitre_addendum_for_prompt

        addendum = mitre_addendum_for_prompt(max_lines=50)
        sys_refine = (
            f"{instruction}\n\n---\n"
            f"Curated MITRE ATT&CK technique reference (subset; align mentions when useful):\n{addendum}"
        )

    timeout = httpx.Timeout(
        connect=10.0,
        read=float(settings.sentinelops_llm_timeout_secs),
        write=30.0,
        pool=10.0,
    )
    async with httpx.AsyncClient(timeout=timeout) as client:
        if not want_cascade:
            user_msg = (
                f"Data and findings from our security platform (JSON and text below):\n\n{context[:190_000]}"
            )
            text = await _chat(
                client,
                model=refine,
                system=sys_refine,
                user=user_msg,
                api_key=api_key,
                base=base,
            )
            return text, refine

        draft_user = f"Data and findings (truncate if very long; extract structure):\n\n{context[:150_000]}"
        draft_text = await _chat(
            client,
            model=draft,
            system=DRAFT_SYSTEM,
            user=draft_user,
            api_key=api_key,
            base=base,
            max_tokens=MAX_DRAFT_TOKENS,
            temperature=0.1,
        )
        refine_user = (
            "Here is a **first-pass structured draft** from a smaller model. Use it with the system "
            "instructions to produce the **final** deliverable. If the draft conflicts with policy, prefer "
            "accuracy and say what is unknown.\n\n"
            f"## Draft\n{draft_text}\n"
        )
        final = await _chat(
            client,
            model=refine,
            system=sys_refine,
            user=refine_user,
            api_key=api_key,
            base=base,
        )
        label = f"cascade:{draft}→{refine}"
        return final, label


async def warm_models() -> dict[str, dict[str, object]]:
    """Pre-load draft + refine models with a 1-token prompt; returns timing per model.

    Surfaces a tiny error per model rather than aborting the whole call when one
    model isn't pulled — that lets the UI tell the user exactly what to fix.
    """
    if not llm_is_configured():
        raise LlmNotConfiguredError("No LLM configured.")
    api_key = _effective_api_key()
    base = (settings.sentinelops_llm_base_url or "https://api.openai.com/v1").rstrip("/")
    refine = _refine_model_name()
    draft = _draft_model_name()
    models: list[str] = [m for m in [draft, refine] if m]
    if not models:
        models = [refine]
    seen: set[str] = set()
    unique: list[str] = []
    for m in models:
        if m and m not in seen:
            seen.add(m)
            unique.append(m)

    import time

    timeout = httpx.Timeout(
        connect=10.0,
        read=float(settings.sentinelops_llm_warmup_timeout_secs),
        write=15.0,
        pool=5.0,
    )
    out: dict[str, dict[str, object]] = {}
    async with httpx.AsyncClient(timeout=timeout) as client:
        for model in unique:
            t0 = time.monotonic()
            try:
                text = await _chat(
                    client,
                    model=model,
                    system="Reply with exactly: ok",
                    user="warm",
                    api_key=api_key,
                    base=base,
                    max_tokens=4,
                    temperature=0.0,
                )
                out[model] = {
                    "ok": True,
                    "elapsed_secs": round(time.monotonic() - t0, 2),
                    "sample": text[:32],
                }
            except LlmUpstreamError as exc:
                out[model] = {
                    "ok": False,
                    "elapsed_secs": round(time.monotonic() - t0, 2),
                    "error": str(exc),
                    "status_code": exc.status_code,
                }
    return out
