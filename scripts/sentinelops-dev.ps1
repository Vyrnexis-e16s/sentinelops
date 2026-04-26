<#
  SentinelOps — venvs, Node, typecheck, then Docker Compose (required for full stack).

  Runs on Windows PowerShell 3.0+ and PowerShell 7+ (pwsh). No #Requires line so older
  hosts can at least show a clear error from the version check below.

  Usage (setup / run):
    .\scripts\sentinelops-dev.ps1                    # full: venv + npm + docker compose (required)
    .\scripts\sentinelops-dev.ps1 -Mode local        # venv + npm only (no Docker — for partial work)
    .\scripts\sentinelops-dev.ps1 -Mode docker       # only: docker compose up -d --build
    .\scripts\sentinelops-dev.ps1 -TryUpgradePython  # also: winget upgrade for installed Python
    .\scripts\sentinelops-dev.ps1 -NoWingetPython    # skip auto winget install/upgrade of Python

  Lifecycle commands (instead of setup):
    .\scripts\sentinelops-dev.ps1 -Restart           # bounce every running container
    .\scripts\sentinelops-dev.ps1 -Stop              # stop & remove containers (volumes preserved)
    .\scripts\sentinelops-dev.ps1 -Status            # show docker compose ps for the stack
    .\scripts\sentinelops-dev.ps1 -Logs              # tail last 200 lines of every service
    .\scripts\sentinelops-dev.ps1 -Help              # show full help

  Logs: logs/sentinelops-dev-<timestamp>.log
#>
param(
  [ValidateSet("full", "local", "docker")]
  [string] $Mode = "full",
  [switch] $TryUpgradePython,
  [switch] $NoWingetPython,
  [switch] $Restart,
  [switch] $Stop,
  [switch] $Status,
  [switch] $Logs,
  [switch] $Migrate,
  [switch] $Smoke,
  [switch] $SetupLlm,
  [switch] $All,
  [switch] $Auto,
  [switch] $Bootstrap,
  [switch] $Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
@"
SentinelOps dev runner — sentinelops-dev.ps1

Usage:
  .\scripts\sentinelops-dev.ps1 [SwitchOrCommand]

Lifecycle commands:
  -All        Full bring-up: venvs + npm + force-rebuild Docker stack
              (docker compose up -d --build --force-recreate) + run dev seed.
              Use this for a clean, "everything ready" first-time start.
  -Restart    Apply code/config changes: docker compose up -d --build
              --force-recreate for every service, then wait for /health.
              Rebuilds images that changed and recreates containers so
              volume-mounted source updates are picked up.
  -Stop       Stop and remove all SentinelOps containers via
              'docker compose down'. Named volumes (Postgres / Redis data)
              are preserved.
  -Status     Show 'docker compose ps' for the project.
  -Logs       Tail the last 200 lines of every service.
  -Migrate    Run 'alembic upgrade head' in the running backend container.
  -Smoke      Run scripts/_smoke-all-tools.sh (WSL/bash or Git Bash; API on :8000).
  -SetupLlm   Run scripts/setup-local-llm.ps1 (Ollama: find binary, pull two models, write .env snippet).
  -Auto       SENTINELOPS_AUTO_INSTALL for this run: on Windows, winget Node (and in full flow) if missing; use with -All for full + auto deps where supported.
  -Bootstrap  Check Python/Node/Docker, optionally install via winget when -Auto; then exit. Linux/WSL: use bash script --bootstrap instead.
  -Help       Show this message and exit.

Modes (default = setup):
  -Mode full     venvs + npm + 'docker compose up -d --build' (default)
  -Mode local    venvs + npm only (no Docker)
  -Mode docker   only 'docker compose up -d --build'

Other switches:
  -TryUpgradePython   Run 'winget upgrade' for installed Python before continuing.
  -NoWingetPython     Skip automatic 'winget install/upgrade' of Python.

Examples:
  .\scripts\sentinelops-dev.ps1                # full setup (skip rebuild if already running)
  .\scripts\sentinelops-dev.ps1 -All           # full setup + force rebuild + seed
  .\scripts\sentinelops-dev.ps1 -Restart       # bounce the stack and pick up code changes
  .\scripts\sentinelops-dev.ps1 -Stop          # stop everything (data kept)
  .\scripts\sentinelops-dev.ps1 -Status        # see what is running
  .\scripts\sentinelops-dev.ps1 -Migrate       # alembic upgrade head in backend container
  .\scripts\sentinelops-dev.ps1 -Smoke         # API smoke (WSL or bash on PATH)
  .\scripts\sentinelops-dev.ps1 -SetupLlm     # Ollama: pull qwen2.5 + llama3.1, write .env snippet
"@ | Write-Host
  exit 0
}

# --- PowerShell runtime: 3.0+ (Desktop) and 7+ (Core) both supported ---
$psv = $PSVersionTable.PSVersion
if ($psv.Major -lt 3) {
  Write-Host "ERROR: PowerShell 3.0 or newer is required. You have $psv." -ForegroundColor Red
  Write-Host "Install PowerShell 7: https://aka.ms/powershell" -ForegroundColor Yellow
  exit 1
}
# Do not use $PSEdition / $psEdition — name collides (case-insensitive) with the read-only automatic variable.
$shellKind = "Desktop"
$pe = $PSVersionTable["PSEdition"]
if ($pe) { $shellKind = $pe }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$LogDir = Join-Path $RepoRoot "logs"
$LogFile = Join-Path $LogDir ("sentinelops-dev-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$ComposeFile = Join-Path $RepoRoot "infra\docker\docker-compose.yml"

function Log([string] $m, [string] $lvl = "INFO") {
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format o), $lvl, $m
  Write-Host $line
  if (Test-Path $LogDir) { Add-Content -LiteralPath $LogFile -Value $line }
}
function HasCmd($n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

# Re-read machine + user PATH (needed after winget install in same session)
function Sync-MachinePath {
  $m = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $u = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($m -or $u) { $env:Path = "$m;$u" }
}

function Test-PythonExternallyManaged([string] $Interpreter) {
  $py = @'
import sys, pathlib
v = "%d.%d" % (sys.version_info[0], sys.version_info[1])
for base in (sys.prefix, "/usr", "/usr/local"):
    p = pathlib.Path(base) / "lib" / ("python" + v) / "EXTERNALLY-MANAGED"
    if p.is_file():
        raise SystemExit(0)
raise SystemExit(1)
'@
  $null = & $Interpreter -c $py 2>&1
  return ($LASTEXITCODE -eq 0)
}

function Update-PipForBasePython([string] $Interpreter) {
  if (Test-PythonExternallyManaged -Interpreter $Interpreter) {
    Log "PEP 668 (externally managed Python): skipping system-level pip. Installs use backend/.venv and ml/.venv only."
    return
  }
  Log "ensurepip + pip install --upgrade (base interpreter): $Interpreter"
  $oldEa = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $null = & $Interpreter -m ensurepip --upgrade 2>&1 | Tee-Object -FilePath $LogFile -Append
  $ErrorActionPreference = $oldEa
  $pout = & $Interpreter -m pip install --upgrade pip setuptools wheel 2>&1
  $pec = $LASTEXITCODE
  $pout | Tee-Object -FilePath $LogFile -Append
  if ($pec -ne 0) { Log "pip install --upgrade on base Python exited $pec (continuing; venv will retry)" "WARN" }
}

function Update-PipForVenv([string] $VenvDir) {
  $py = Join-Path $VenvDir "Scripts\python.exe"
  if (-not (Test-Path -LiteralPath $py)) { return }
  $null = & $py -m pip --version 2>&1
  if ($LASTEXITCODE -ne 0) {
    Log "Bootstrapping pip in venv: $VenvDir (ensurepip)"
    $oldEa = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $null = & $py -m ensurepip --upgrade 2>&1 | Tee-Object -FilePath $LogFile -Append
    $ErrorActionPreference = $oldEa
  }
  $null = & $py -m pip --version 2>&1
  if ($LASTEXITCODE -ne 0) {
    Log "venv has no pip. Remove the folder and re-run, and install python3-venv (Linux) or repair Python. Path: $VenvDir" "ERROR"
    exit 1
  }
}

# Invoke "docker compose" (v2) or legacy "docker-compose" (v1); logs stdout/stderr to $LogFile
function Invoke-DockerCompose {
  param([string[]] $ComposeArgs)
  Push-Location $RepoRoot
  try {
    if (HasCmd "docker") {
      $null = & docker compose version 2>&1
      if ($LASTEXITCODE -eq 0) {
        $out = & docker compose -f $ComposeFile @ComposeArgs 2>&1
        $ec = $LASTEXITCODE
        $out | Tee-Object -FilePath $LogFile -Append
        return $ec
      }
    }
    if (HasCmd "docker-compose") {
      $out = & docker-compose -f $ComposeFile @ComposeArgs 2>&1
      $ec = $LASTEXITCODE
      $out | Tee-Object -FilePath $LogFile -Append
      return $ec
    }
  } finally {
    Pop-Location
  }
  return 127
}

function Test-DockerEngine {
  if (-not (HasCmd "docker")) { return $false }
  $null = & docker info 2>&1
  return ($LASTEXITCODE -eq 0)
}

# True if every service in the compose file has a running container (docker compose v2), or v1 heuristics
function Test-SentinelopsComposeAllRunning {
  if (-not (Test-DockerEngine)) { return $false }
  Push-Location $RepoRoot
  try {
    if (HasCmd "docker") {
      $null = & docker compose version 2>&1
      if ($LASTEXITCODE -eq 0) {
        $raw = & docker compose -f $ComposeFile config --services 2>&1
        if ($LASTEXITCODE -ne 0) { return $false }
        $nExp = @($raw -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }).Count
        if ($nExp -lt 1) { return $false }
        $runOut = & docker compose -f $ComposeFile ps -q --status running 2>&1
        if ($LASTEXITCODE -ne 0) { return $false }
        $nRun = @($runOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }).Count
        return ($nRun -ge $nExp)
      }
    }
    if (HasCmd "docker-compose") {
      $raw = & docker-compose -f $ComposeFile config --services 2>&1
      if ($LASTEXITCODE -ne 0) { return $false }
      $nExp = @($raw -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }).Count
      if ($nExp -lt 1) { return $false }
      $t = & docker-compose -f $ComposeFile ps 2>&1
      if ($LASTEXITCODE -ne 0) { return $false }
      $nUp = 0
      foreach ($line in ($t -split '\r?\n')) {
        if ($line -match '^\s*NAME\s' -or $line -match '^\s*-\s*-\s*-') { continue }
        if ($line -match '\s+Up(\s+|\(|\Z)') { $nUp++ }
      }
      return ($nUp -ge $nExp)
    }
  } finally {
    Pop-Location
  }
  return $false
}

function Start-SentinelopsCompose {
  if ($script:ForceBuild) {
    Log "docker compose up -d --build --force-recreate (-All: forced fresh start)"
    return (Invoke-DockerCompose @("up", "-d", "--build", "--force-recreate"))
  }
  if (Test-SentinelopsComposeAllRunning) {
    Log "Docker / Docker Compose: stack for $ComposeFile is already up (all services running). Skipping: docker compose up -d --build"
    return 0
  }
  Log "docker compose up -d --build (starting or rebuilding stack)"
  return (Invoke-DockerCompose @("up", "-d", "--build"))
}

function Invoke-SentinelopsSeed {
  Log "Seeding development data (docker compose exec backend python -m app.scripts.seed)…"
  $code = (Invoke-DockerCompose @("exec", "-T", "backend", "python", "-m", "app.scripts.seed"))
  if ($code -ne 0) {
    Log "seed exited $code (often OK on re-run when data already exists)" "WARN"
  }
}

# -All implies force-rebuild + seed at the end of the full pipeline.
$script:ForceBuild = $false
$script:RunSeed = $false
if ($All) {
  $script:ForceBuild = $true
  $script:RunSeed = $true
}
if ($Auto) {
  $env:SENTINELOPS_AUTO_INSTALL = "1"
}

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Log "PowerShell $psv ($shellKind) | Mode=$Mode | Repo=$RepoRoot | Log=$LogFile"

# .env
$ex = Join-Path $RepoRoot ".env.example"
$ef = Join-Path $RepoRoot ".env"
if (-not (Test-Path $ef) -and (Test-Path $ex)) {
  Copy-Item $ex $ef
  Log "Created .env from .env.example"
}

function Wait-BackendHealth {
  for ($i = 0; $i -lt 30; $i++) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8000/health" -TimeoutSec 3 -ErrorAction Stop
      if ($r.StatusCode -eq 200) {
        Log "Backend /health: ok"
        return
      }
    } catch { }
    Start-Sleep -Seconds 2
  }
  Log "Backend /health did not return OK within ~60s (it may still be migrating). Check: docker compose -f infra/docker/docker-compose.yml logs backend" "WARN"
}

# --- lifecycle: -Stop / -Restart / -Status / -Logs / -Migrate / -Smoke / -SetupLlm (short-circuit) ---
if ($Stop -or $Restart -or $Status -or $Logs -or $Migrate -or $Smoke -or $SetupLlm) {
  if (-not (Test-DockerEngine)) {
    Log "Docker is not installed or the engine is not running. Start Docker Desktop, then retry." "ERROR"
    exit 1
  }
  if ($Stop) {
    Log "Stopping SentinelOps stack (docker compose down — volumes preserved)…"
    $code = (Invoke-DockerCompose @("down"))
    if ($code -ne 0) { Log "docker compose down failed (exit $code). See: $LogFile" "ERROR"; exit 1 }
    Log "Stopped. Run '.\scripts\sentinelops-dev.ps1' to bring it back up."
    exit 0
  }
  if ($Restart) {
    Log "Restarting SentinelOps stack: docker compose up -d --build --force-recreate"
    Log "  (rebuilds images that changed; recreates every container so volume-mounted source is reread)"
    $code = (Invoke-DockerCompose @("up", "-d", "--build", "--force-recreate"))
    if ($code -ne 0) { Log "docker compose up failed (exit $code). See: $LogFile" "ERROR"; exit 1 }
    Wait-BackendHealth
    Log "UI http://localhost:3000  |  API http://localhost:8000/docs"
    exit 0
  }
  if ($Status) {
    $null = (Invoke-DockerCompose @("ps"))
    exit 0
  }
  if ($Logs) {
    $null = (Invoke-DockerCompose @("logs", "--tail", "200", "--no-color"))
    exit 0
  }
  if ($Migrate) {
    Log "Running alembic upgrade head in backend container…"
    $code = (Invoke-DockerCompose @("exec", "-T", "backend", "alembic", "upgrade", "head"))
    if ($code -ne 0) { Log "alembic failed. Is the stack up? Try: -Restart" "ERROR"; exit 1 }
    Log "Migrations applied."
    exit 0
  }
  if ($Smoke) {
    $smSh = Join-Path $ScriptDir "_smoke-all-tools.sh"
    if (-not (Test-Path -LiteralPath $smSh)) { Log "Missing $smSh" "ERROR"; exit 1 }
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
      $u = (wsl wslpath $RepoRoot 2>$null).Trim()
      if ([string]::IsNullOrEmpty($u)) { Log "wsl wslpath failed. Open WSL once, then retry." "ERROR"; exit 1 }
      $bashCmd = "set -euo pipefail; cd " + $u.Replace("'", "'\''") + " && bash ./scripts/_smoke-all-tools.sh"
      wsl -e bash -lc $bashCmd
      exit $LASTEXITCODE
    }
    if (Get-Command bash -ErrorAction SilentlyContinue) {
      Push-Location $RepoRoot
      & bash "./scripts/_smoke-all-tools.sh"
      $c = $LASTEXITCODE
      Pop-Location
      exit $c
    }
    Log "Install WSL or add Git Bash to run the smoke script, or use Linux/WSL." "ERROR"
    exit 1
  }
  if ($SetupLlm) {
    $ps1 = Join-Path $ScriptDir "setup-local-llm.ps1"
    if (-not (Test-Path -LiteralPath $ps1)) { Log "Missing $ps1" "ERROR"; exit 1 }
    & $ps1
    exit $LASTEXITCODE
  }
}

# --- docker only ---
if ($Mode -eq "docker") {
  if (-not (Test-DockerEngine)) {
    Log "Docker is not installed or the engine is not running. Start Docker Desktop, then retry." "ERROR"
    Log "  https://docs.docker.com/desktop/install/windows-install/" "ERROR"
    exit 1
  }
  $code = (Start-SentinelopsCompose)
  if ($code -ne 0) { Log "docker compose failed (exit $code). See: $LogFile" "ERROR"; exit 1 }
  Log "http://localhost:3000  |  http://localhost:8000/docs"
  exit 0
}

# --- resolve Python 3.11+ executable ---
function Get-PythonPath {
  $code = "import sys; assert sys.version_info>=(3,11); print(sys.executable)"
  if (HasCmd "py") {
    $out = & py -3.13 -c $code 2>$null; if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
    $out = & py -3.12 -c $code 2>$null; if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
    $out = & py -3.11 -c $code 2>$null; if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
  }
  foreach ($c in @("python3.13", "python3.12", "python3.11", "python3", "python")) {
    if (-not (HasCmd $c)) { continue }
    $out = & $c -c $code 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
  }
  return $null
}

# --- -Bootstrap: report and optional winget, then exit (before full setup) ---
if ($Bootstrap) {
  Log "— Prerequisite check (this machine) —"
  $pyTry = Get-PythonPath
  if ($pyTry) { Log "Python 3.11+: OK  $pyTry" } else { Log "Python 3.11+: MISSING" "WARN" }
  if (HasCmd "node") { Log "Node: $(node -v)" } else { Log "Node: MISSING" "WARN" }
  if (Test-DockerEngine) { Log "Docker: engine OK" } else { Log "Docker: not available or not running" "WARN" }
  if ($Auto -and (HasCmd "winget")) {
    if (-not (HasCmd "node")) {
      Log "AUTO: winget install OpenJS.NodeJS.LTS"
      $ErrorActionPreference = "Continue"
      winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
      $ErrorActionPreference = "Stop"
      Sync-MachinePath
    }
    if (-not (Get-PythonPath) -and -not $NoWingetPython) {
      Log "AUTO: winget install Python.Python.3.12"
      $ErrorActionPreference = "Continue"
      winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
      $ErrorActionPreference = "Stop"
      Sync-MachinePath
    }
    if (-not (Test-DockerEngine)) {
      Log "For Docker: https://docs.docker.com/desktop/install/windows-install/  or: winget install -e --id Docker.DockerDesktop" "WARN"
    }
  } elseif ($Auto) {
    Log "AUTO set but winget not on PATH; install tools manually, or use WSL + bash scripts with --auto." "WARN"
  }
  Log "On apt Linux:  SENTINELOPS_AUTO_INSTALL=1 ./scripts/sentinelops-dev.sh --all --auto"
  exit 0
}

$PythonPath = Get-PythonPath
if ($TryUpgradePython -and (HasCmd "winget") -and -not $NoWingetPython -and $PythonPath) {
  Log "TryUpgradePython: winget upgrade (Python 3.13, then 3.12 if needed)"
  $ErrorActionPreference = "Continue"
  $null = winget upgrade -e --id Python.Python.3.13 --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
  if ($LASTEXITCODE -ne 0) {
    $null = winget upgrade -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
  }
  $ErrorActionPreference = "Stop"
  Sync-MachinePath
  $PythonPath = Get-PythonPath
}
if (-not $PythonPath -and (HasCmd "winget") -and -not $NoWingetPython) {
  Log "Python 3.11+ not found; installing Python 3.12 via winget…"
  $ErrorActionPreference = "Continue"
  winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
  $ErrorActionPreference = "Stop"
  Sync-MachinePath
  $PythonPath = Get-PythonPath
}
if (-not $PythonPath -and (HasCmd "winget") -and -not $NoWingetPython) {
  Log "winget: trying Python 3.13…" "WARN"
  $ErrorActionPreference = "Continue"
  winget install -e --id Python.Python.3.13 --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
  $ErrorActionPreference = "Stop"
  Sync-MachinePath
  $PythonPath = Get-PythonPath
}
if (-not $PythonPath) {
  Log "Need Python 3.11+ on PATH. Install from https://www.python.org/downloads/ or: winget install Python.Python.3.12" "ERROR"
  Log "  Use -NoWingetPython to skip automatic winget install." "ERROR"
  exit 1
}
Log "Python: $(& $PythonPath -c "import sys; print(sys.executable, sys.version)" 2>&1 | Out-String).Trim()"

# pip on base interpreter (then venvs get a fresh copy)
Update-PipForBasePython -Interpreter $PythonPath

# --- venv: backend ---
$bd = Join-Path $RepoRoot "backend"
$bn = Join-Path $bd ".venv\Scripts\python.exe"
if (-not (Test-Path $bn)) {
  Log "Creating backend\.venv"
  Push-Location $bd; & $PythonPath -m venv .venv; Pop-Location
}
$bn = Join-Path $bd ".venv\Scripts\python.exe"
Update-PipForVenv -VenvDir (Join-Path $bd ".venv")
& $bn -m pip install --upgrade pip 2>&1 | Tee-Object -FilePath $LogFile -Append
& $bn -m pip install -r (Join-Path $bd "requirements.txt") 2>&1 | Tee-Object -FilePath $LogFile -Append
if ($LASTEXITCODE -ne 0) { Log "backend pip install failed" "ERROR"; exit 1 }

# --- venv: ml ---
$ml = Join-Path $RepoRoot "ml"
$mn = Join-Path $ml ".venv\Scripts\python.exe"
$mlreq = Join-Path $ml "requirements.txt"
if (Test-Path $mlreq) {
  if (-not (Test-Path $mn)) {
    Log "Creating ml\.venv"
    Push-Location $ml; & $PythonPath -m venv .venv; Pop-Location
  }
  $mn = Join-Path $ml ".venv\Scripts\python.exe"
  Update-PipForVenv -VenvDir (Join-Path $ml ".venv")
  & $mn -m pip install --upgrade pip 2>&1 | Tee-Object -FilePath $LogFile -Append
  & $mn -m pip install -r $mlreq 2>&1 | Tee-Object -FilePath $LogFile -Append
  if ($LASTEXITCODE -ne 0) { Log "ml pip had warnings" "WARN" }
}

# --- Node 20+ (Next.js 16 / frontend) ---
if (-not (HasCmd "node") -and $env:SENTINELOPS_AUTO_INSTALL -eq "1" -and (HasCmd "winget")) {
  Log "AUTO: installing Node.js LTS via winget…"
  $ErrorActionPreference = "Continue"
  winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
  $ErrorActionPreference = "Stop"
  Sync-MachinePath
}
if (-not (HasCmd "node")) {
  Log "Install Node 20+ (nodejs.org) or: winget install OpenJS.NodeJS.LTS" "ERROR"
  exit 1
}
$maj = [int]((node -v) -replace "v(\d+).*", '$1')
if ($maj -lt 20) { Log "Node 20+ required for the Next.js 16 frontend" "ERROR"; exit 1 }
Log "Node: $(node -v)"

# --- frontend install + checks ---
$fe = Join-Path $RepoRoot "frontend"
Set-Location $fe
if (HasCmd "pnpm") {
  pnpm install 2>&1 | Tee-Object -FilePath $LogFile -Append
  pnpm run typecheck 2>&1 | Tee-Object -FilePath $LogFile -Append
  if ($LASTEXITCODE -ne 0) { Log "Frontend typecheck failed" "ERROR"; exit 1 }
  pnpm run lint 2>&1 | Tee-Object -FilePath $LogFile -Append
} else {
  npm install 2>&1 | Tee-Object -FilePath $LogFile -Append
  npm run typecheck 2>&1 | Tee-Object -FilePath $LogFile -Append
  if ($LASTEXITCODE -ne 0) { Log "Frontend typecheck failed" "ERROR"; exit 1 }
  npm run lint 2>&1 | Tee-Object -FilePath $LogFile -Append
}
Set-Location $RepoRoot

# --- Full stack: Docker Compose is required (DB, Redis, API, UI, worker) ---
if ($Mode -eq "full") {
  if (-not (Test-DockerEngine)) {
    Log "Full setup requires Docker with a running engine (Postgres, Redis, backend, worker, frontend)." "ERROR"
    Log "Install and start Docker Desktop, then re-run. Or use -Mode local to skip containers." "ERROR"
    Log "  https://docs.docker.com/desktop/install/windows-install/" "ERROR"
    exit 1
  }
  $dc = (Start-SentinelopsCompose)
  if ($dc -ne 0) {
    Log "docker compose failed (exit $dc). See log: $LogFile" "ERROR"
    exit 1
  }
  if ($script:RunSeed) {
    Wait-BackendHealth
    Invoke-SentinelopsSeed
  }
  Log "Stack is up. UI http://localhost:3000  |  API http://localhost:8000/docs"
  Log "Seed development data: docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed"
}

Log "Finished OK"
Write-Host ""
if ($Mode -eq "full") {
  Write-Host "Docker services are running. For local dev without Docker, use: .\scripts\sentinelops-dev.ps1 -Mode local"
} else {
  Write-Host "Run backend:  cd backend; .\.venv\Scripts\Activate.ps1; uvicorn app.main:app --reload --host 127.0.0.1"
  Write-Host "Run frontend: cd frontend; pnpm dev"
}
exit 0
