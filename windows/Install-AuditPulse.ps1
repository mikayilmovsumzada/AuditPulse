#Requires -Version 5.1
<#
.SYNOPSIS
  Installs (or updates) AuditPulse on Windows. Run in PowerShell opened "as Administrator".

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\windows\Install-AuditPulse.ps1
  powershell -ExecutionPolicy Bypass -File .\windows\Install-AuditPulse.ps1 -Watch "C:\inetpub" -Unwatch "C:\Users\Public"
  powershell -ExecutionPolicy Bypass -File .\windows\Install-AuditPulse.ps1 -SetPassword

.DESCRIPTION
  1. Turns on Windows file auditing ("Audit File System", success and failure). The previous
     audit policy is backed up once to C:\ProgramData\AuditPulse\auditpol-backup.csv.
  2. Copies the program to C:\Program Files\AuditPulse and keeps its data in
     C:\ProgramData\AuditPulse (readable only by SYSTEM and Administrators).
  3. Adds an audit rule (SACL) to each watched folder so Windows logs who changed what.
  4. Registers the scheduled task "AuditPulse" that runs as SYSTEM at startup, restarts on
     failure, and starts it now. The panel is at http://localhost:8088
#>
param(
    [string[]]$Watch = @(),
    [string[]]$Unwatch = @(),
    [switch]$SetPassword,
    [int]$Port = 0,
    [int]$SecurityLogSizeMB = 0
)

$ErrorActionPreference = 'Stop'
$TaskName = 'AuditPulse'
$Repo = Split-Path -Parent $PSScriptRoot
$Dest = Join-Path $env:ProgramFiles 'AuditPulse'
$DataDir = Join-Path $env:ProgramData 'AuditPulse'
$FileSystemAudit = '{0CCE921D-69AE-11D9-BED3-505054503030}'   # Object Access > File System
$AuthzPolicyAudit = '{0CCE9231-69AE-11D9-BED3-505054503030}'  # Policy Change > Authorization Policy Change (4670)

function Step([string]$Text) { Write-Host "`n$Text" -ForegroundColor Cyan }

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'PowerShell-i "Run as administrator" ilə açıb bu skripti yenidən işlədin.'
}
foreach ($f in 'windows\AuditPulse.ps1', 'web\index.html') {
    if (-not (Test-Path -LiteralPath (Join-Path $Repo $f))) { throw "Fayl tapılmadı: $f. Skripti AuditPulse qovluğunun içindən işlədin." }
}

# Folder checks and config helpers are shared with the service.
. (Join-Path $Repo 'windows\AuditPulse.ps1') -LibraryOnly -DataDir $DataDir

Step '[1/5] Məlumat qovluğu hazırlanır...'
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
# Events contain user names and file paths: only SYSTEM and Administrators may read them.
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
$cfg = Get-Config
$firstInstall = -not (Test-Path -LiteralPath $ConfigFile)
if ($firstInstall) {
    $cfg.folders = @(@((Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Documents'), (Join-Path $env:USERPROFILE 'Downloads')) |
        Where-Object { Test-Path -LiteralPath $_ -PathType Container } | ForEach-Object { (Get-Item -LiteralPath $_).FullName.TrimEnd('\') })
}
if ($Port) { $cfg.port = $Port }

# Port conflict: something other than AuditPulse already listening?
$busy = Get-NetTCPConnection -State Listen -LocalPort $cfg.port -ErrorAction SilentlyContinue
if ($busy) {
    $owners = @($busy | ForEach-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } | Select-Object -Unique)
    $ours = (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -and ($owners -contains 'System' -or $owners -contains 'powershell')
    if (-not $ours) { throw "Port $($cfg.port) artıq istifadə olunur ($($owners -join ', ')). Başqa port seçin, məsələn: -Port 8090" }
}

if ($SetPassword) {
    $p1 = Read-Host 'Panel üçün yeni parol (ən azı 12 simvol)' -AsSecureString
    $p2 = Read-Host 'Parolu təkrar yazın' -AsSecureString
    $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
    $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
    if ($plain1 -ne $plain2) { throw 'Parollar eyni deyil.' }
    if ($plain1.Length -lt 12) { throw 'Parol ən azı 12 simvol olmalıdır.' }
    $salt = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $iter = 210000
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($plain1, $salt, $iter, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $cfg.passwordHash = 'pbkdf2-sha256:{0}:{1}:{2}' -f $iter, [Convert]::ToBase64String($salt), [Convert]::ToBase64String($kdf.GetBytes(32))
    $kdf.Dispose(); $plain1 = $null; $plain2 = $null
    Write-Host 'Parol yadda saxlandı. Brauzer paneli açanda parol soruşacaq (istifadəçi adına istənilən söz yazın).'
}

Step '[2/5] Windows fayl auditi yandırılır...'
$backup = Join-Path $DataDir 'auditpol-backup.csv'
if (-not (Test-Path -LiteralPath $backup)) { & auditpol.exe /backup /file:$backup | Out-Null }
& auditpol.exe /set /subcategory:$FileSystemAudit /success:enable /failure:enable | Out-Null
& auditpol.exe /set /subcategory:$AuthzPolicyAudit /success:enable | Out-Null
if ($SecurityLogSizeMB -gt 0) { & wevtutil.exe sl Security /ms:$([int64]$SecurityLogSizeMB * 1MB) | Out-Null }

Step '[3/5] İzlənən qovluqlar...'
foreach ($raw in $Unwatch) {
    $hit = @($cfg.folders | Where-Object { $_ -ieq $raw.TrimEnd('\') })
    if (-not $hit) { Write-Host "  ! $raw izlənmirdi"; continue }
    try { Set-FolderAudit $hit[0] $false } catch { Write-Host "  ! audit qaydası silinmədi: $($_.Exception.Message)" }
    $cfg.folders = @($cfg.folders | Where-Object { $_ -ine $hit[0] })
    Write-Host "  - $($hit[0])"
}
foreach ($raw in $Watch) {
    try { $path = Resolve-NewFolder $raw @($cfg.folders) } catch { Write-Host "  ! ${raw}: $($_.Exception.Message)"; continue }
    $cfg.folders = @($cfg.folders + $path)
    Write-Host "  + $path"
}
foreach ($f in $cfg.folders) {
    # Re-applying is harmless: an identical rule is merged, not duplicated.
    try { Set-FolderAudit $f $true; Write-Host "  izlənir: $f" } catch { Write-Host "  ! ${f}: audit qaydası qoyulmadı ($($_.Exception.Message))" }
}
Save-Config $cfg

Step '[4/5] Proqram köçürülür...'
$wasRunning = (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -and ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running')
if ($wasRunning) { Stop-ScheduledTask -TaskName $TaskName; Start-Sleep -Seconds 2 }
New-Item -ItemType Directory -Force -Path (Join-Path $Dest 'windows'), (Join-Path $Dest 'web') | Out-Null
Copy-Item -LiteralPath (Join-Path $Repo 'windows\AuditPulse.ps1') -Destination (Join-Path $Dest 'windows\AuditPulse.ps1') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'web\index.html') -Destination (Join-Path $Dest 'web\index.html') -Force
Get-ChildItem -LiteralPath $Dest -Recurse -File | Unblock-File

Step '[5/5] Servis (planlaşdırılmış tapşırıq) qeydiyyatdan keçir və başladılır...'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dest\windows\AuditPulse.ps1`""
# "Restart on failure" only covers a failed launch, not a process that exits later, so a
# second trigger re-checks every 5 minutes; IgnoreNew makes it a no-op while the service runs.
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$trigger = @((New-ScheduledTaskTrigger -AtStartup), $watchdog)
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Description 'AuditPulse: fayl audit paneli (http://localhost)' `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$url = "http://localhost:$($cfg.port)/"
$ok = $false
for ($i = 0; $i -lt 45 -and -not $ok; $i++) {
    Start-Sleep -Seconds 1
    try { Invoke-WebRequest -Uri "${url}api/meta" -UseBasicParsing -TimeoutSec 2 | Out-Null; $ok = $true }
    catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $ok = $true } }
}
if ($ok) {
    Write-Host "`nHazırdır! Brauzerdə açın: $url" -ForegroundColor Green
    Write-Host "İzlənən qovluqlar: $($cfg.folders -join ', ')"
    if (-not $cfg.passwordHash) { Write-Host 'Qovluqları paneldən dəyişmək üçün parol qoyun: -SetPassword' }
} else {
    Write-Host "`nServis başlamadı. Səbəbə baxın: $DataDir\auditpulse.log" -ForegroundColor Yellow
    exit 1
}
