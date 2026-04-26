# Local LLM setup for VAPT (Ollama + two-step cascade)

SentinelOps calls an **OpenAI-compatible** `POST /v1/chat/completions` endpoint. [Ollama](https://ollama.com) exposes that on your machine, so you can run **open-weight models** locally without sending data to a cloud API.

The backend supports two modes:

- **Single model** — one completion with `SENTINELOPS_LLM_MODEL` only (omit or leave `SENTINELOPS_LLM_DRAFT_MODEL` empty, or set `SENTINELOPS_LLM_CASCADE=0`).
- **Two-step cascade (recommended on GPU/CPU for balance)** — a **draft** model structures facts; a **refine** model writes the final executive triage. Same base URL, different `model` names in each request.

Default tags used by the repo scripts: **draft** `qwen2.5:7b`, **refine** `llama3.1:8b` (you can change them).

---

## 1. Install Ollama

1. Download and install for your OS: **https://ollama.com/**  
2. Start the Ollama app (Windows/macOS) or ensure the service runs (`ollama serve` on Linux if needed).  
3. Confirm the API is up:

   ```bash
   curl -s http://127.0.0.1:11434/ | head
   ```

4. **Hardware:** Larger models need more RAM/VRAM. If 8B+ models are slow, use smaller tags (e.g. `qwen2.5:3b` / `llama3.2:3b`) in `.env`.

---

## 2. Pull models and generate `.env` snippet (recommended)

From the **repo root** (paths are resolved automatically; nothing user-specific is hardcoded):

**Linux / WSL / macOS (bash)**

```bash
./scripts/sentinelops-dev.sh --setup-llm
# or
bash scripts/setup-local-llm.sh
```

**Windows (PowerShell)**

```powershell
.\scripts\sentinelops-dev.ps1 -SetupLlm
# or
.\scripts\setup-local-llm.ps1
```

**Override model names** (optional, same shell for both platforms):

```bash
export SENTINELOPS_LLM_DRAFT_MODEL=qwen2.5:7b
export SENTINELOPS_LLM_MODEL=llama3.1:8b
bash scripts/setup-local-llm.sh
```

This will:

- Find `ollama` on your `PATH` (and a few common install locations on Windows).  
- Run `ollama pull` for the draft and refine tags.  
- Write **`./.env.llm.local.generated`** with the right variable names. **Do not commit this file** if it contains secrets; the generated snippet is safe to merge as-is for local Ollama.

---

## 3. Merge into `.env` (repo root)

1. If you have no `.env` yet, copy: `cp .env.example .env` (or let the dev script do it).  
2. **Append** the contents of `.env.llm.local.generated` to `.env`, or paste the variables manually.  
3. **Minimum for local Ollama:**

   | Variable | Example | Purpose |
   |----------|---------|--------|
   | `SENTINELOPS_LLM_OLLAMA` | `1` | Allow calls without a real OpenAI key (uses `Bearer ollama`). |
   | `OPENAI_API_KEY` | `ollama` | Placeholder; real cloud keys still work if you set this to an actual key. |
   | `SENTINELOPS_LLM_BASE_URL` | `http://127.0.0.1:11434/v1` | Ollama OpenAI-compatible base (**must** end in `/v1` for the backend). |
   | `SENTINELOPS_LLM_DRAFT_MODEL` | `qwen2.5:7b` | First pass (structured draft). |
   | `SENTINELOPS_LLM_MODEL` | `llama3.1:8b` | Second pass (final VAPT text). |
   | `SENTINELOPS_LLM_CASCADE` | `1` | Enable two-step when draft ≠ refine. |

4. **Disable cascade** (single model only): clear `SENTINELOPS_LLM_DRAFT_MODEL` or set `SENTINELOPS_LLM_CASCADE=0`, and set only `SENTINELOPS_LLM_MODEL`.

5. **Cloud instead of local:** set a real `OPENAI_API_KEY`, `SENTINELOPS_LLM_BASE_URL=https://api.openai.com/v1` (or your provider), and `SENTINELOPS_LLM_OLLAMA=0`. Leave `SENTINELOPS_LLM_DRAFT_MODEL` empty unless you want a paid two-step with two different API models.

---

## 4. Backend in Docker, Ollama on the host

The API container must reach the host at **host.docker.internal** (or the host gateway on Linux).

**Example (merge into `.env` used by Compose):**

```env
SENTINELOPS_LLM_BASE_URL=http://host.docker.internal:11434/v1
```

**Linux (Docker 20.10+):** add to the `backend` service in `infra/docker/docker-compose.yml`:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Then restart: `./scripts/sentinelops-dev.sh --restart` (or your usual compose command).  
If that fails, use your host LAN IP, e.g. `http://192.168.1.10:11434/v1`, with firewall rules allowing the Docker bridge to reach the host.

**WSL:** Ollama on Windows, API in Linux Docker: `host.docker.internal` from the container usually works on Docker Desktop; otherwise use the Windows host IP from WSL2.

---

## 5. Restart the API and verify

- After editing `.env`, **restart the backend** so settings reload.  
- In the app: open **VAPT** → “Assemble from live API” (optional) → **Generate triage (LLM)**.  
- If the LLM is not configured, you get **503** with a message (not fake text).  
- In the response metadata / UI, a cascade run shows a model string like `cascade:qwen2.5:7b→llama3.1:8b`.

**Quick API check (with a JWT or from logs):**

```http
POST /api/v1/vapt/llm/summarize
```

Body: `{"context":"test","inject_mitre_context":false,"use_cascade":true}` (adjust as needed).

---

## 6. VAPT UI options

- **Append curated MITRE** — adds the bundled technique list to the **refine** system prompt (no live MITRE API).  
- **Two-step (draft+refine)** — uses cascade when the server has `SENTINELOPS_LLM_DRAFT_MODEL` set and `use_cascade: true` (default in UI). Turn off in the UI to force a **single** completion with `SENTINELOPS_LLM_MODEL` only.

---

## 7. Troubleshooting

| Symptom | What to check |
|--------|----------------|
| 503 “No LLM configured” | `SENTINELOPS_LLM_OLLAMA=1` for Ollama without a cloud key, or a real `OPENAI_API_KEY`. |
| 502 from provider | Model name must match `ollama list` exactly; Ollama running; `curl http://127.0.0.1:11434/`. |
| 502 in Docker, OK on host | `SENTINELOPS_LLM_BASE_URL` and `host.docker.internal` / `extra_hosts` (see §4). |
| Very slow / OOM | Use smaller tags; close other apps; on CPU, expect long waits. |
| Only one model wanted | Unset `SENTINELOPS_LLM_DRAFT_MODEL` or set `SENTINELOPS_LLM_CASCADE=0`. |

**Logs:** `docker compose ... logs backend` (Compose) or your terminal for local `uvicorn`.

---

## 8. Same stack without Ollama (vLLM, LM Studio, etc.)

Anything that exposes **OpenAI-compatible** `POST /v1/chat/completions` with `Authorization: Bearer <key>` works. Set `SENTINELOPS_LLM_BASE_URL` to that service’s base (including `/v1`), and `OPENAI_API_KEY` to whatever that server requires (or a dummy if it ignores it). Two-model cascade still uses `SENTINELOPS_LLM_DRAFT_MODEL` + `SENTINELOPS_LLM_MODEL` as the `model` field in two requests.

---

## 9. Related commands

| Task | Command |
|------|--------|
| Prereq check (Linux apt) | `./scripts/sentinelops-dev.sh --bootstrap` |
| Full stack + best-effort OS deps (apt + Auto) | `./scripts/sentinelops-dev.sh --all --auto` |
| Ollama models + `.env` snippet | `./scripts/sentinelops-dev.sh --setup-llm` |

See also: `scripts/README.md`, root `.env.example` (VAPT section).
