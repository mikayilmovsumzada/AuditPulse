#Requires -Version 5.1
<#
.SYNOPSIS
  Removes AuditPulse from Windows. Run in PowerShell opened "as Administrator".

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\windows\Uninstall-AuditPulse.ps1
  powershell -ExecutionPolicy Bypass -File .\windows\Uninstall-AuditPulse.ps1 -RemoveData -RestoreAuditPolicy

.DESCRIPTION
  Stops and removes the "AuditPulse" scheduled task, removes the audit rules (SACL) it added to
  the watched folders and deletes C:\Program Files\AuditPulse.
  -RemoveData          also deletes the collected events and settings (C:\ProgramData\AuditPulse).
  -RestoreAuditPolicy  restores the Windows audit policy saved before the first install.
#>
param([switch]$RemoveData, [switch]$RestoreAuditPolicy)

$ErrorActionPreference = 'Stop'
$TaskName = 'AuditPulse'
$Dest = Join-Path $env:ProgramFiles 'AuditPulse'
$DataDir = Join-Path $env:ProgramData 'AuditPulse'

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'PowerShell-i "Run as administrator" ilə açıb bu skripti yenidən işlədin.'
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host 'Servis dayandırıldı və silindi.'
}

$lib = Join-Path $Dest 'windows\AuditPulse.ps1'
if (Test-Path -LiteralPath $lib) {
    . $lib -LibraryOnly -DataDir $DataDir
    foreach ($f in (Get-Config).folders) {
        try { Set-FolderAudit $f $false; Write-Host "Audit qaydası silindi: $f" } catch { Write-Host "! ${f}: $($_.Exception.Message)" }
    }
}

if ($RestoreAuditPolicy) {
    $backup = Join-Path $DataDir 'auditpol-backup.csv'
    if (Test-Path -LiteralPath $backup) { & auditpol.exe /restore /file:$backup | Out-Null; Write-Host 'Audit siyasəti əvvəlki vəziyyətinə qaytarıldı.' }
    else { Write-Host '! Audit siyasətinin ehtiyat nüsxəsi tapılmadı.' }
}

if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force; Write-Host "Silindi: $Dest" }
if ($RemoveData -and (Test-Path -LiteralPath $DataDir)) { Remove-Item -LiteralPath $DataDir -Recurse -Force; Write-Host "Silindi: $DataDir" }
Write-Host 'AuditPulse silindi.'
