<#
  Make a host-installed Ollama (native Windows OR a WSL2 distro) listen on
  0.0.0.0:<port> so a Docker container (e.g. SentinelOps backend) can reach it
  via host.docker.internal.

  Default Ollama installs bind to 127.0.0.1:11434 — the container cannot reach
  that even with `extra_hosts: host-gateway`. This script:
    * Native Windows : sets the User-scope OLLAMA_HOST environment variable and,
                       if Ollama Desktop is running, restarts it so the new env
                       takes effect.
    * WSL2 distro    : runs scripts/bind-ollama-host.sh inside a WSL distro that
                       has Ollama as a systemd service. Auto-detects the right
                       distro (the one that contains an ollama.service unit).

  Idempotent — re-running is safe.

  Usage:
    .\scripts\bind-ollama-host.ps1                # detect and apply
    .\scripts\bind-ollama-host.ps1 -Bind 0.0.0.0  # explicit bind addr
    .\scripts\bind-ollama-host.ps1 -Port 11500    # custom port
    .\scripts\bind-ollama-host.ps1 -Force         # always set Windows env var even if Ollama isn't installed natively
    .\scripts\bind-ollama-host.ps1 -SkipWsl       # never touch WSL even when a distro has ollama.service
#>
param(
  [string] $Bind = "0.0.0.0",
  [int] $Port = 11434,
  [switch] $Force,
  [switch] $SkipWsl
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$LogDir = Join-Path $RepoRoot "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("bind-ollama-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

function Log([string] $m) {
  $line = "[bind-ollama] $m"
  Write-Host $line
  Add-Content -LiteralPath $LogFile -Value $line
}

function HasCmd($n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

$Target = "${Bind}:${Port}"

# --- Probe: is Ollama listening only on 127.0.0.1? -------------------------
function Test-OllamaLocalOnly {
  $listeners = @()
  try { $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop } catch { return $null }
  if (-not $listeners -or $listeners.Count -eq 0) { return $null }   # nothing on that port
  $hasAny  = $false
  $hasLoop = $false
  foreach ($c in $listeners) {
    if ($c.LocalAddress -in @("0.0.0.0", "::", "*")) { $hasAny = $true }
    elseif ($c.LocalAddress -in @("127.0.0.1", "::1")) { $hasLoop = $true }
  }
  if ($hasAny) { return $false }   # already on all ifaces
  if ($hasLoop) { return $true }   # only loopback — needs rebind
  return $false                    # bound to a specific iface, leave alone
}

# --- Native Windows path ---------------------------------------------------
function Find-OllamaNative {
  if (HasCmd "ollama") { return (Get-Command ollama).Path }
  $cands = @(
    (Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"),
    (Join-Path $env:ProgramFiles "Ollama\ollama.exe")
  )
  $pf86 = [Environment]::GetFolderPath("ProgramFilesX86")
  if ($pf86) { $cands += (Join-Path $pf86 "Ollama\ollama.exe") }
  foreach ($p in $cands) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
  return $null
}

function Set-WindowsOllamaHost {
  param([string] $TargetEnv)
  $current = [Environment]::GetEnvironmentVariable("OLLAMA_HOST", "User")
  if ($current -eq $TargetEnv) {
    Log "User OLLAMA_HOST already set to $TargetEnv (no change)."
  } else {
    Log "Setting User OLLAMA_HOST=$TargetEnv (persisted; survives reboot)."
    [Environment]::SetEnvironmentVariable("OLLAMA_HOST", $TargetEnv, "User")
    $env:OLLAMA_HOST = $TargetEnv  # also for current session
  }
  # Stop any running tray app + serve so the new env is picked up on relaunch.
  $running = Get-Process -Name "ollama","ollama app" -ErrorAction SilentlyContinue
  if ($running) {
    Log "Stopping running ollama processes so the new env var is picked up…"
    foreach ($p in $running) {
      try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { Log "  could not stop PID $($p.Id): $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 2
    $exe = Find-OllamaNative
    if ($exe) {
      Log "Relaunching: $exe"
      try { Start-Process -FilePath $exe -ArgumentList "serve" -WindowStyle Hidden | Out-Null }
      catch { Log "  Start-Process failed: $($_.Exception.Message). Re-open Ollama manually." }
    } else {
      Log "Ollama exe not found on disk — re-open the Ollama app manually."
    }
  } else {
    Log "Ollama is not currently running. Launch it (or 'ollama serve') and the new bind takes effect."
  }
}

# --- WSL path --------------------------------------------------------------
function Find-WslDistroWithOllama {
  if ($SkipWsl) { return $null }
  if (-not (HasCmd "wsl")) { return $null }
  $listing = (& wsl -l -q 2>$null)
  if (-not $listing) { return $null }
  $names = @()
  foreach ($line in ($listing -split "\r?\n")) {
    $t = ($line -replace "`0","").Trim()
    if ($t) { $names += $t }
  }
  foreach ($d in $names) {
    $probe = & wsl -d $d -e bash -lc "test -f /etc/systemd/system/ollama.service -o -f /usr/lib/systemd/system/ollama.service -o -f /lib/systemd/system/ollama.service && echo yes" 2>$null
    if ($probe -match "yes") { return $d }
  }
  return $null
}

function Invoke-WslBindScript {
  param([string] $Distro)
  $u = (& wsl -d $Distro wslpath $RepoRoot 2>$null).Trim()
  if ([string]::IsNullOrEmpty($u)) {
    Log "WSL: wslpath failed for $Distro — open the distro once, then retry." 
    return $false
  }
  $cmd = "set -e; cd '" + $u.Replace("'", "'\''") + "' && OLLAMA_BIND=$Bind OLLAMA_PORT=$Port bash ./scripts/bind-ollama-host.sh"
  Log "WSL($Distro): running scripts/bind-ollama-host.sh (will use sudo inside WSL)…"
  & wsl -d $Distro -e bash -lc $cmd
  return ($LASTEXITCODE -eq 0)
}

# --- main ------------------------------------------------------------------
$state = Test-OllamaLocalOnly
$nativeExe = Find-OllamaNative
$wslDistro = Find-WslDistroWithOllama

Log "Probe: native ollama exe = $([bool]$nativeExe); WSL distro with ollama.service = $wslDistro; loopback-only on port $Port = $state"

if (-not $nativeExe -and -not $wslDistro -and -not $Force) {
  Log "ERROR: no native Ollama and no WSL distro with ollama.service found."
  Log "  Install Ollama on Windows (https://ollama.com/download) or in a WSL distro,"
  Log "  or pass -Force to set the User OLLAMA_HOST env var anyway."
  exit 1
}

$did = $false
if ($wslDistro) {
  if ((Invoke-WslBindScript -Distro $wslDistro)) {
    $did = $true
  } else {
    Log "WSL bind helper exited non-zero. Falling back to Windows env var if applicable."
  }
}
if ($nativeExe -or $Force) {
  if ($state -eq $true -or $Force -or -not $did) {
    Set-WindowsOllamaHost -TargetEnv $Target
    $did = $true
  } else {
    Log "Native Ollama on Windows already listens on all interfaces (or isn't loopback-only) — skipping env override."
  }
}

if (-not $did) {
  Log "Nothing to do."
  exit 0
}

# Verify
Start-Sleep -Seconds 2
$after = Test-OllamaLocalOnly
if ($null -eq $after) {
  Log "Port $Port currently shows no listener — Ollama may still be starting. Check after a few seconds."
} elseif ($after -eq $true) {
  Log "WARN: still loopback-only on port $Port. If you used the Windows tray app, fully quit it (right-click → Quit) and relaunch."
} else {
  Log "OK: Ollama is reachable on all interfaces (port $Port)."
  Log "Containers on the same host can now reach it via http://host.docker.internal:$Port/v1"
}

Log "Log file: $LogFile"
Log "Done."
exit 0
