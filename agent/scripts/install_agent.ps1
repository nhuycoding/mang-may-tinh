#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install OGK-Agent Windows Service (LocalSystem), configure strict Windows ACLs on
    C:\ProgramData\OGK-Agent, configure SCM Service Recovery Options, and register Tray UI auto-start.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$PythonExe = (Get-Command python).Source,
    [Parameter(Mandatory=$false)]
    [string]$ProjectRoot = (Resolve-Path "$PSScriptRoot\..\..").Path,
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureLocalDNS
)

$ErrorActionPreference = "Stop"
$DataDir = "C:\ProgramData\OGK-Agent"

Write-Host "[OGK] 1. Creating local storage directory: $DataDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Host "[OGK] 2. Hardening Windows ACLs (only SYSTEM and Administrators have write permissions)..." -ForegroundColor Cyan
icacls $DataDir /inheritance:r | Out-Null
icacls $DataDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null

Write-Host "[OGK] 3. Installing OGKAgent Windows Service (LocalSystem)..." -ForegroundColor Cyan
Push-Location $ProjectRoot
try {
    & $PythonExe -m agent.src.service.windows_service --startup=auto install
} finally {
    Pop-Location
}

Write-Host "[OGK] 4. Configuring SCM Service Recovery Options (auto-restart on failure)..." -ForegroundColor Cyan
sc.exe failure OGKAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
sc.exe failureflag OGKAgent 1 | Out-Null

Write-Host "[OGK] 5. Registering OGK Tray UI for interactive user sessions (HKLM Run)..." -ForegroundColor Cyan
$TrayCmd = "`"$PythonExe`" -m agent.src.tray.tray_app"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "KidGateTray" -Value $TrayCmd

if ($ConfigureLocalDNS) {
    Write-Host "[OGK] 6. Pointing active network adapters DNS to 127.0.0.1 (Local DNS Proxy)..." -ForegroundColor Cyan
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ("127.0.0.1")
    }
}

Write-Host "[OGK] Starting OGKAgent service..." -ForegroundColor Green
Start-Service -Name "OGKAgent" -ErrorAction SilentlyContinue
Write-Host "[OGK] Installation complete! Enroll first if not enrolled: python -m agent.scripts.enroll ..." -ForegroundColor Green
