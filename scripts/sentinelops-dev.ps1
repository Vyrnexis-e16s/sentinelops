#Requires -Version 5.1
<#
  SentinelOps — venvs, requirements, Node install, typecheck, optional Docker.
  Logs: logs/sentinelops-dev-<timestamp>.log

  Usage:
    .\scripts\sentinelops-dev.ps1
    .\scripts\sentinelops-dev.ps1 -Mode local      # no docker
    .\scripts\sentinelops-dev.ps1 -Mode docker     # only docker compose
    .\scripts\sentinelops-dev.ps1 -TryUpgradePython  # try winget Python 3.12 if <3.11
#>
param(
  [ValidateSet("full", "local", "docker")]
  [string] $Mode = "full",
  [switch] $SkipDocker,
  [switch] $TryUpgradePython
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$LogDir = Join-Path $RepoRoot "logs"
$LogFile = Join-Path $LogDir ("sentinelops-dev-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

function Log([string] $m, [string] $lvl = "INFO") {
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format o), $lvl, $m
  Write-Host $line
  if (Test-Path $LogDir) { Add-Content -LiteralPath $LogFile -Value $line }
}
function HasCmd($n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Log "Repository: $RepoRoot | Mode=$Mode | Log=$LogFile"

# .env
$ex = Join-Path $RepoRoot ".env.example"
$ef = Join-Path $RepoRoot ".env"
if (-not (Test-Path $ef) -and (Test-Path $ex)) {
  Copy-Item $ex $ef
  Log "Created .env from .env.example"
}

# --- docker only ---
if ($Mode -eq "docker") {
  if (-not (HasCmd "docker")) { Log "Install Docker Desktop first." "ERROR"; exit 1 }
  Set-Location $RepoRoot
  docker compose -f "infra/docker/docker-compose.yml" up -d --build 2>&1 | Tee-Object -FilePath $LogFile -Append
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

# --- optional docker ---
if ($Mode -eq "full" -and -not $SkipDocker) {
  if (HasCmd "docker") {
    Log "docker compose up -d --build"
    docker compose -f "infra/docker/docker-compose.yml" up -d --build 2>&1 | Tee-Object -FilePath $LogFile -Append
    Log "Open http://localhost:3000 | Seed: docker compose -f infra/docker/docker-compose.yml exec backend python -m app.scripts.seed"
  } else {
    Log "Docker not in PATH; skipped" "WARN"
  }
}

Log "Finished OK"
Write-Host ""
Write-Host "Run locally:"
Write-Host "  backend:  cd backend; .\.venv\Scripts\Activate.ps1; uvicorn app.main:app --reload --host 127.0.0.1"
Write-Host "  frontend: cd frontend; pnpm dev"
exit 0
