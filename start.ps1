# Starts the backend API and the admin Vite app on Windows. Ctrl-C stops both.
# Run with: powershell -ExecutionPolicy Bypass -File .\start.ps1
$ErrorActionPreference = 'Stop'

Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot 'backend\.venv\Scripts\python.exe'
# npm.cmd, not npm: the npm.ps1 shim can't load under the default execution policy.
$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath $python) -or -not $npm -or -not (Test-Path -LiteralPath 'admin\node_modules')) {
    Write-Error 'Setup is incomplete. Follow "Set up (first time only)" in README.md first.'
}

# Prompt for the key unless it's already in the environment.
$promptedForKey = -not $env:GEMINI_API_KEY
if ($promptedForKey) {
    $secureKey = Read-Host -Prompt 'GEMINI_API_KEY' -AsSecureString
    $env:GEMINI_API_KEY = [Net.NetworkCredential]::new('', $secureKey).Password
}
if (-not $env:GEMINI_API_KEY) {
    Write-Error 'GEMINI_API_KEY is required.'
}

$servers = @()
try {
    $servers += Start-Process -FilePath $python -PassThru -NoNewWindow `
        -WorkingDirectory (Join-Path $PSScriptRoot 'backend') `
        -ArgumentList '-m', 'uvicorn', 'app.main:app', '--reload', '--host', '127.0.0.1', '--port', '8741'
    $servers += Start-Process -FilePath $npm.Source -PassThru -NoNewWindow `
        -WorkingDirectory (Join-Path $PSScriptRoot 'admin') `
        -ArgumentList 'run', 'dev'

    # If either server exits, stop the other one too.
    while (-not ($servers | Where-Object HasExited)) {
        Start-Sleep -Milliseconds 500
    }
    $serverExited = $true
}
finally {
    # This also runs on Ctrl-C. /T reaches each server's children (uvicorn's
    # reloader worker, npm's node process). Redirecting inside cmd keeps
    # taskkill's stderr out of PowerShell, where 5.1 would raise it as an error.
    foreach ($server in $servers) {
        if (-not $server.HasExited) {
            cmd.exe /d /c "taskkill /T /F /PID $($server.Id) >nul 2>&1"
        }
    }
    # Don't leave the key behind in a shell session that outlives this script.
    if ($promptedForKey) {
        Remove-Item Env:GEMINI_API_KEY -ErrorAction SilentlyContinue
    }
}

if ($serverExited) {
    Write-Host 'A server exited, so both have been stopped.'
    exit 1
}
