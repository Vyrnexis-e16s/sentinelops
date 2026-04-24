<#
  SentinelOps — venvs, Node, typecheck, then Docker Compose (required for full stack).

  Runs on Windows PowerShell 3.0+ and PowerShell 7+ (pwsh). No #Requires line so older
  hosts can at least show a clear error from the version check below.

  Usage:
    .\scripts\sentinelops-dev.ps1                    # full: venv + npm + docker compose (required)
    .\scripts\sentinelops-dev.ps1 -Mode local        # venv + npm only (no Docker — for partial work)
    .\scripts\sentinelops-dev.ps1 -Mode docker       # only: docker compose up -d --build
    .\scripts\sentinelops-dev.ps1 -TryUpgradePython  # optional winget Python 3.12

  Logs: logs/sentinelops-dev-<timestamp>.log
#>
param(
  [ValidateSet("full", "local", "docker")]
  [string] $Mode = "full",
  [switch] $TryUpgradePython
)

$ErrorActionPreference = "Stop"

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

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Log "PowerShell $psv ($shellKind) | Mode=$Mode | Repo=$RepoRoot | Log=$LogFile"

# .env
$ex = Join-Path $RepoRoot ".env.example"
$ef = Join-Path $RepoRoot ".env"
if (-not (Test-Path $ef) -and (Test-Path $ex)) {
  Copy-Item $ex $ef
  Log "Created .env from .env.example"
}

# --- docker only ---
if ($Mode -eq "docker") {
  if (-not (Test-DockerEngine)) {
    Log "Docker is not installed or the engine is not running. Start Docker Desktop, then retry." "ERROR"
    Log "  https://docs.docker.com/desktop/install/windows-install/" "ERROR"
    exit 1
  }
  $code = Invoke-DockerCompose @("up", "-d", "--build")
  if ($code -ne 0) { Log "docker compose failed (exit $code). See: $LogFile" "ERROR"; exit 1 }
  Log "http://localhost:3000  |  http://localhost:8000/docs"
  exit 0
}

# --- resolve Python 3.11+ executable ---
function Get-PythonPath {
  $code = "import sys; assert sys.version_info>=(3,11); print(sys.executable)"
  if (HasCmd "py") {
    $out = & py -3.12 -c $code 2>$null; if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
    $out = & py -3.11 -c $code 2>$null; if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
    $out = & py -3.13 -c $code 2>$null; if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
  }
  foreach ($c in @("python3.12", "python3.11", "python3", "python")) {
    if (-not (HasCmd $c)) { continue }
    $out = & $c -c $code 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
  }
  return $null
}

$PythonPath = Get-PythonPath
if (-not $PythonPath -and $TryUpgradePython -and (HasCmd "winget")) {
  Log "Trying winget: Python.Python.3.12" "WARN"
  winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $LogFile -Append
  $PythonPath = Get-PythonPath
}
if (-not $PythonPath) {
  Log "Need Python 3.11+ on PATH (use py launcher, or install from python.org). Then re-run." "ERROR"
  Log "  winget install Python.Python.3.12" "ERROR"
  exit 1
}
Log "Python: $(& $PythonPath -c "import sys; print(sys.version)" 2>&1 | Out-String).Trim()"

# --- venv: backend ---
$bd = Join-Path $RepoRoot "backend"
$bn = Join-Path $bd ".venv\Scripts\python.exe"
if (-not (Test-Path $bn)) {
  Log "Creating backend\.venv"
  Push-Location $bd; & $PythonPath -m venv .venv; Pop-Location
}
$bn = Join-Path $bd ".venv\Scripts\python.exe"
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
  & $mn -m pip install --upgrade pip 2>&1 | Tee-Object -FilePath $LogFile -Append
  & $mn -m pip install -r $mlreq 2>&1 | Tee-Object -FilePath $LogFile -Append
  if ($LASTEXITCODE -ne 0) { Log "ml pip had warnings" "WARN" }
}

# --- Node 18+ ---
if (-not (HasCmd "node")) {
  Log "Install Node 18+ (nodejs.org) or: winget install OpenJS.NodeJS.LTS" "ERROR"
  exit 1
}
$maj = [int]((node -v) -replace "v(\d+).*", '$1')
if ($maj -lt 18) { Log "Node 18+ required" "ERROR"; exit 1 }
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
  Log "docker compose up -d --build (required for full application stack)"
  $dc = Invoke-DockerCompose @("up", "-d", "--build")
  if ($dc -ne 0) {
    Log "docker compose failed (exit $dc). See log: $LogFile" "ERROR"
    exit 1
  }
  Log "Stack is up. UI http://localhost:3000  |  API http://localhost:8000/docs"
  Log "Seed demo data: docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed"
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
