param(
    [ValidateSet("normal", "port_scan", "syn_flood")]
    [string]$Scenario = "port_scan",
    [switch]$InstallFrontend
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($InstallFrontend) {
    Push-Location (Join-Path $Root "frontend")
    npm ci
    Pop-Location
}

$env:PYTHONPATH = Join-Path $Root "engine"
$api = Start-Process -FilePath "python" `
    -ArgumentList "-m uvicorn api.main:app --host 127.0.0.1 --port 8000" `
    -WorkingDirectory $Root -PassThru
$frontend = Start-Process -FilePath "npm" `
    -ArgumentList "run dev -- --host 127.0.0.1" `
    -WorkingDirectory (Join-Path $Root "frontend") -PassThru

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:8000/api/health"
            if ($health.status -eq "ok") {
                $ready = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        throw "API did not become ready on http://127.0.0.1:8000"
    }

    python (Join-Path $Root "traffic\replay\demo_replay.py") `
        --scenario $Scenario --api "http://127.0.0.1:8000"
    Write-Host "`nSENTINEL-X demo is running." -ForegroundColor Green
    Write-Host "Dashboard: http://localhost:5173"
    Write-Host "Scenario:  $Scenario"
    Write-Host "Press Ctrl+C to stop this launcher. Child windows may be closed separately."
    while ($true) {
        Start-Sleep -Seconds 2
    }
} finally {
    if ($api -and -not $api.HasExited) { Stop-Process -Id $api.Id -Force }
    if ($frontend -and -not $frontend.HasExited) { Stop-Process -Id $frontend.Id -Force }
}
