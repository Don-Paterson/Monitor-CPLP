<#
.SYNOPSIS
    Monitor-CPLP bootstrap
    Installs Python (if needed) + Flask + Paramiko on A-GUI, downloads the tool,
    shows a menu to pick the lab (CCTE / CCSE-ElasticXL / CTPS / custom) and the
    machines to watch, then starts the dashboard that tracks Check Point Live Patch
    (CPLP, sk185114): 'cplp list' status per patch, the URGENT bundle take vs the
    latest in the SK, CVE coverage and the AutoUpdater / consent settings behind it.

.USAGE
    irm https://raw.githubusercontent.com/Don-Paterson/Monitor-CPLP/main/bootstrap.ps1 | iex

    Optional overrides (set before running):
      $env:CPLP_USER     = 'admin'       # Gaia SSH user
      $env:CPLP_PASSWORD = 'Chkp!234'    # Gaia SSH password
      $env:CPLP_EXPERT   = 'Chkp!234'    # expert password (defaults to CPLP_PASSWORD)
      $env:CPLP_RESET    = '1'           # overwrite existing config.json / credentials.json

.NOTES
    - Nothing is changed on the Check Point hosts: collection is read-only over SSH.
      The admin shell is left as-is (Clish is handled by entering expert mode per session).
    - Existing data/ and logs/ are kept, so re-running keeps the original baseline.
    - Runs alongside Monitor-CPLP: different folder (C:\Monitor-CPLP) and port (8091).
#>

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---- Configuration ----
$REPO_URL    = "https://raw.githubusercontent.com/Don-Paterson/Monitor-CPLP/main"
$INSTALL_DIR = "C:\Monitor-CPLP"
$PYTHON_URL  = "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe"

$SSH_USER    = if ($env:CPLP_USER)     { $env:CPLP_USER }     else { "admin" }
$SSH_PASS    = if ($env:CPLP_PASSWORD) { $env:CPLP_PASSWORD } else { 'Chkp!234' }
$EXPERT_PASS = if ($env:CPLP_EXPERT)   { $env:CPLP_EXPERT }   else { $SSH_PASS }
$RESET       = ($env:CPLP_RESET -eq "1")

$FILES = @(
    "server.py",
    "cplpmon/__init__.py",
    "cplpmon/gaia_shell.py",
    "cplpmon/parsers.py",
    "cplpmon/collector.py",
    "cplpmon/differ.py",
    "cplpmon/kb.py",
    "cplpmon/store.py",
    "cplpmon/engine.py",
    "cplpmon/labs.py",
    "cplpmon/menu.py",
    "labs.json",
    "cplp_kb.json",
    "static/dashboard.html",
    "credentials.json.example"
)

function Write-Step($n, $total, $msg) { Write-Host "[$n/$total] $msg" -ForegroundColor Yellow }
function Write-Ok($msg)   { Write-Host "  $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "  $msg" -ForegroundColor White }
function Write-Warn($msg) { Write-Host "  $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "  $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Monitor-CPLP bootstrap" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ---- Helper: find a real Python 3.9+ (ignores the Microsoft Store alias stub) ----
function Find-Python {
    $cands = @()
    $cmd = Get-Command python -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "*WindowsApps*" }
    if ($cmd) { $cands += $cmd.Source }
    $cands += @(
        "C:\Program Files\Python313\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    )
    foreach ($c in $cands) {
        if ($c -and (Test-Path $c)) {
            $v = (& $c --version 2>&1 | Out-String)
            if ($v -match "Python 3\.(\d+)" -and [int]$Matches[1] -ge 9) { return $c }
        }
    }
    return $null
}

# ---- Step 1: Python ----
Write-Step 1 5 "Checking Python..."
$PY = Find-Python
if ($PY) {
    Write-Ok "Found $(& $PY --version 2>&1) at $PY"
} else {
    Write-Info "Downloading Python 3.12..."
    $pyInstaller = "$env:TEMP\python-3.12-installer.exe"
    Invoke-WebRequest -Uri $PYTHON_URL -OutFile $pyInstaller -UseBasicParsing
    Write-Info "Installing Python (silent, all users)..."
    Start-Process -FilePath $pyInstaller -ArgumentList `
        "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_pip=1", "Include_test=0" `
        -Wait -NoNewWindow
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User")
    $PY = Find-Python
    if (-not $PY) { Write-Err "Python install failed - install Python 3.12 manually and re-run."; return }
    Write-Ok "Python installed: $PY"
}

# ---- Step 2: Python packages ----
Write-Step 2 5 "Installing Python packages (flask, paramiko)..."
& $PY -m pip install --quiet --disable-pip-version-check --upgrade pip 2>$null
& $PY -m pip install --quiet --disable-pip-version-check flask paramiko 2>$null
$check = & $PY -c "import flask, paramiko; print('ok')" 2>&1
if ("$check" -match "ok") { Write-Ok "flask + paramiko ready" } else { Write-Err "Package install problem: $check"; return }

# ---- Step 3: Download files (keeps data/, logs/, config, credentials) ----
Write-Step 3 5 "Downloading Monitor-CPLP to $INSTALL_DIR..."
foreach ($d in @($INSTALL_DIR, "$INSTALL_DIR\cplpmon", "$INSTALL_DIR\static")) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
$failed = 0
foreach ($file in $FILES) {
    $dest = Join-Path $INSTALL_DIR ($file -replace "/", "\")
    try {
        Invoke-WebRequest -Uri "$REPO_URL/$file" -OutFile $dest -UseBasicParsing
    } catch {
        Write-Err "Failed: $file ($($_.Exception.Message))"; $failed++
    }
}
$cfgPath = Join-Path $INSTALL_DIR "config.json"
if ($RESET -or -not (Test-Path $cfgPath)) {
    Invoke-WebRequest -Uri "$REPO_URL/config.json" -OutFile $cfgPath -UseBasicParsing
    Write-Info "config.json written (defaults)"
} else {
    Write-Info "Keeping existing config.json (set `$env:CPLP_RESET='1' to replace it)"
}
if ($failed) { Write-Err "$failed file(s) failed to download"; return }
Write-Ok "Files in place"

# ---- Step 4: Credentials ----
Write-Step 4 5 "Credentials..."
$credPath = Join-Path $INSTALL_DIR "credentials.json"
if ($RESET -or -not (Test-Path $credPath)) {
    $cred = @{ ssh = @{ user = $SSH_USER; password = $SSH_PASS; expert_password = $EXPERT_PASS } }
    ($cred | ConvertTo-Json -Depth 3) | Out-File -FilePath $credPath -Encoding ascii
    Write-Ok "credentials.json created (SSH user: $SSH_USER)"
} else {
    Write-Ok "Keeping existing credentials.json"
}

# ---- Step 5: Launcher + start ----
Write-Step 5 5 "Creating launcher and starting dashboard..."
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$launcher = Join-Path $INSTALL_DIR "Start-Monitor.cmd"
@"
@echo off
title Monitor-CPLP
cd /d "$INSTALL_DIR"
"$PY" server.py
pause
"@ | Out-File -FilePath $launcher -Encoding ascii
try {
    $lnkPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "Monitor-CPLP.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = $launcher
    $lnk.WorkingDirectory = $INSTALL_DIR
    $lnk.Save()
    Write-Ok "Desktop shortcut: Monitor-CPLP"
} catch { Write-Warn "Could not create desktop shortcut: $_" }

$port = if ($cfg.dashboard.port) { $cfg.dashboard.port } else { 8091 }
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Monitor-CPLP ready" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Dashboard : http://localhost:$port" -ForegroundColor White
Write-Host "  Folder    : $INSTALL_DIR" -ForegroundColor White
Write-Host "  Change log: $INSTALL_DIR\logs\<lab>\changes.log" -ForegroundColor White
Write-Host "  One-off   : `"$PY`" $INSTALL_DIR\server.py --once" -ForegroundColor White
Write-Host ""
Write-Host "  Labs      : CCTE, CCSE-ElasticXL, CTPS + your own in labs.local.json" -ForegroundColor White
Write-Host "  CPLP KB   : $INSTALL_DIR\cplp_kb.json (sk185114 - refreshed on every bootstrap run)" -ForegroundColor White
Write-Host "  Skip menu : `"$PY`" $INSTALL_DIR\server.py --last" -ForegroundColor White
Write-Host ""
Write-Host "Starting - choose the lab and machines in the menu (Ctrl+C to stop; relaunch from the desktop shortcut)..." -ForegroundColor Yellow
Write-Host ""

Set-Location $INSTALL_DIR
& $PY server.py
