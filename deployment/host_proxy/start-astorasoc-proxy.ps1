$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProxyScript = Join-Path $ScriptDir "astorasoc_proxy.py"
$LogDir = Join-Path $ScriptDir "logs"
$OutLog = Join-Path $LogDir "astorasoc-proxy.out.log"
$ErrLog = Join-Path $LogDir "astorasoc-proxy.err.log"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$existing = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Port 5000 is already in use. Stop the existing service before starting AstoraSOC proxy."
    exit 1
}

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) {
    Write-Host "Python was not found in PATH."
    exit 1
}

Start-Process -FilePath $python `
    -ArgumentList @("`"$ProxyScript`"", "--listen-host", "0.0.0.0", "--listen-port", "5000", "--backend-host", "127.0.0.1", "--backend-port", "5001") `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -WindowStyle Hidden

Write-Host "AstoraSOC proxy started on port 5000. Logs: $OutLog $ErrLog"
