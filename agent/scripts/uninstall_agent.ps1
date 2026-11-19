#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Cleanly uninstall OGK-Agent Windows Service, remove Tray UI startup entry, and restore DNS to DHCP.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$PythonExe = (Get-Command python).Source,
    [Parameter(Mandatory=$false)]
    [string]$ProjectRoot = (Resolve-Path "$PSScriptRoot\..\..").Path,
    [Parameter(Mandatory=$false)]
    [switch]$PurgeData
)

$ErrorActionPreference = "Continue"

Write-Host "[OGK] 1. Restoring DNS settings to DHCP on active adapters..." -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
}

Write-Host "[OGK] 2. Stopping and removing OGKAgent Windows Service..." -ForegroundColor Cyan
Stop-Service -Name "OGKAgent" -Force -ErrorAction SilentlyContinue
Push-Location $ProjectRoot
try {
    & $PythonExe -m agent.src.service.windows_service remove
} finally {
    Pop-Location
}

Write-Host "[OGK] 3. Removing Tray UI auto-start entry..." -ForegroundColor Cyan
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OGKCompanionTray" -ErrorAction SilentlyContinue

if ($PurgeData) {
    Write-Host "[OGK] 4. Removing C:\ProgramData\OGK-Agent..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "C:\ProgramData\OGK-Agent" -ErrorAction SilentlyContinue
}

Write-Host "[OGK] Uninstall completed." -ForegroundColor Green
