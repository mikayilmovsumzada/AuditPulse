#Requires -Version 5.1
<#
.SYNOPSIS
  AuditPulse for Windows: watches chosen folders and serves the same dashboard as the Linux version.

.DESCRIPTION
  What changed comes from FileSystemWatcher (create, delete, modify, rename).
  Who did it and with which program comes from the Windows Security log
  (4663 object access, 4670 permission change, 4656 failed access), which needs
  "Audit File System" enabled and an audit rule (SACL) on each watched folder.
  Install-AuditPulse.ps1 sets both up and runs this script as SYSTEM at startup.

  Stdlib only: Windows PowerShell 5.1 and .NET Framework, nothing to download.
#>
param(
    [string]$DataDir = (Join-Path $env:ProgramData 'AuditPulse'),
    [string]$WebDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'web'),
    [int]$Port = 0,
    # Install-AuditPulse.ps1 dot-sources this file with -LibraryOnly to reuse the folder checks.
    [switch]$LibraryOnly
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$ConfigFile = Join-Path $DataDir 'config.json'
$EventsFile = Join-Path $DataDir 'events.jsonl'
$LogFile = Join-Path $DataDir 'auditpulse.log'
$MaxEvents = 50000
$MaxWatches = 16
$AuthWindow = 900
$AuthMaxFails = 5
$EveryoneSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$AuditRights = [System.Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
$Suggested = @(
    (Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Documents'), (Join-Path $env:USERPROFILE 'Downloads'),
    'C:\Users\Public', 'C:\inetpub', (Join-Path $env:SystemRoot 'System32\drivers\etc'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
)

function Write-Log([string]$Text) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Text
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
    Write-Host $line
}

# ------------------------------------------------------------------ config

function Get-Config {
    $cfg = @{ host = '127.0.0.1'; port = 8088; folders = @(); passwordHash = ''; allowedHosts = @() }
    if (Test-Path -LiteralPath $ConfigFile) {
        $raw = Get-Content -LiteralPath $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $raw.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
    }
    $cfg.folders = @($cfg.folders | Where-Object { $_ })
    $cfg.allowedHosts = @($cfg.allowedHosts | Where-Object { $_ })
    return $cfg
}

function Save-Config($cfg) {
    $tmp = "$ConfigFile.tmp"
    ($cfg | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $ConfigFile -Force
}

function Test-Password([string]$Given, [string]$Stored) {
    # pbkdf2-sha256:<iterations>:<salt b64>:<hash b64>, written by Install-AuditPulse.ps1 -SetPassword
    $parts = $Stored -split ':'
    if ($parts.Count -ne 4 -or $parts[0] -ne 'pbkdf2-sha256') { return $false }
    $salt = [Convert]::FromBase64String($parts[2]); $expected = [Convert]::FromBase64String($parts[3])
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Given, $salt, [int]$parts[1], [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $actual = $kdf.GetBytes($expected.Length); $kdf.Dispose()
    $diff = 0
    for ($i = 0; $i -lt $expected.Length; $i++) { $diff = $diff -bor ($expected[$i] -bxor $actual[$i]) }
    return $diff -eq 0
}

# ----------------------------------------------------------------- folders

function Get-FolderKey([string]$Path) {
    $k = ($Path.ToLowerInvariant() -replace '[^a-z0-9]+', '_').Trim('_')
    if ($k.Length -gt 24) { $k = $k.Substring($k.Length - 24).Trim('_') }
    if (-not $k) { $k = 'dir' }
    return $k
}

function Test-Inside([string]$Path, [string]$Root) {
    $p = $Path.TrimEnd('\') + '\'; $r = $Root.TrimEnd('\') + '\'
    return $p.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-NewFolder([string]$Raw, [string[]]$Current) {
    if (-not $Raw -or $Raw.Length -gt 240 -or $Raw -notmatch '^[A-Za-z]:\\') { throw [ArgumentException]'Tam yol yazın, məsələn C:\inetpub' }
    if ($Raw -match '[\x00-\x1f]') { throw [ArgumentException]'Yolda xüsusi simvol ola bilməz' }
    if (-not (Test-Path -LiteralPath $Raw -PathType Container)) { throw [ArgumentException]"Belə qovluq yoxdur: $Raw" }
    $path = (Get-Item -LiteralPath $Raw -Force).FullName.TrimEnd('\')
    if ($path -match '^[A-Za-z]:$') { throw [ArgumentException]'Bütün diski izləmək olmaz: hər saniyə minlərlə hadisə yaranar' }
    foreach ($bad in @($env:SystemRoot, $DataDir, (Join-Path $env:SystemDrive 'ProgramData'), (Join-Path $env:SystemDrive 'Program Files'), (Join-Path $env:SystemDrive 'Program Files (x86)'))) {
        if ((Test-Inside $bad $path) -or ((Test-Inside $path $bad) -and -not (Test-Inside $path (Join-Path $env:SystemRoot 'System32\drivers\etc')) -and -not (Test-Inside $path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu')))) {
            throw [ArgumentException]"$bad izlənə bilməz (sistem qovluğudur və ya panelin öz faylları oradadır)"
        }
    }
    foreach ($d in $Current) {
        if (Test-Inside $path $d) { throw [ArgumentException]"$path artıq izlənir ($d qovluğunun içindədir)" }
        if (Test-Inside $d $path) { throw [ArgumentException]"$path artıq izlənən $d qovluğunu əhatə edir. Əvvəlcə $d-ni çıxarın" }
    }
    if ($Current.Count -ge $MaxWatches) { throw [ArgumentException]"Ən çoxu $MaxWatches qovluq izlənə bilər" }
    return $path
}

function New-AuditRule {
    New-Object System.Security.AccessControl.FileSystemAuditRule($EveryoneSid, $AuditRights,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]'Success, Failure')
}

function Set-FolderAudit([string]$Path, [bool]$Enable) {
    # Only the audit section (SACL) is read and written; permissions and owner stay untouched.
    $item = Get-Item -LiteralPath $Path -Force
    $sec = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
    if ($Enable) { $sec.AddAuditRule((New-AuditRule)) } else { $sec.RemoveAuditRuleSpecific((New-AuditRule)) }
    $item.SetAccessControl($sec)
}

# ------------------------------------------------------------------ events

$script:Events = New-Object System.Collections.Generic.List[object]
$script:NextId = 1

function Load-Events {
    if (-not (Test-Path -LiteralPath $EventsFile)) { return }
    $lines = Get-Content -LiteralPath $EventsFile -Encoding UTF8 -Tail $MaxEvents
    foreach ($l in $lines) {
        if (-not $l) { continue }
        try { $e = $l | ConvertFrom-Json } catch { continue }
        $script:Events.Add($e)
        if ($e.id -ge $script:NextId) { $script:NextId = [int]$e.id + 1 }
    }
    if ($lines.Count -ge $MaxEvents) { $lines | Set-Content -LiteralPath $EventsFile -Encoding UTF8 }  # trim the file
}

function Add-AuditEvent([hashtable]$E) {
    $E.id = $script:NextId; $script:NextId++
    $obj = [pscustomobject]$E
    $script:Events.Add($obj)
    if ($script:Events.Count -gt $MaxEvents) { $script:Events.RemoveRange(0, $script:Events.Count - $MaxEvents) }
    try { Add-Content -LiteralPath $EventsFile -Value ($obj | ConvertTo-Json -Compress) -Encoding UTF8 } catch { }
}

function Get-UnixNow { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 }

function Test-HiddenPath([string]$Path) {
    foreach ($seg in $Path.Split('\')) {
        # Dot folders (.git, .venv, .next…), Office lock files, app data and build/dependency folders
        # change constantly; they are kept but hidden by default, like dot files on Linux.
        if ($seg.StartsWith('.') -or $seg.StartsWith('~$') -or $seg -in @('AppData', '$RECYCLE.BIN', 'node_modules', '__pycache__')) { return $true }
    }
    return ($Path -match '\.(tmp|temp|crdownload|partial)$')
}

function Get-WatchKey([string]$Path) {
    foreach ($f in $script:Config.folders) { if (Test-Inside $Path $f) { return (Get-FolderKey $f) } }
    return $null
}

# Security log facts per path, used to fill in user and program for FileSystemWatcher changes.
$script:SecByPath = @{}
$script:SecStatus = 'unknown'
$script:SecLog = $null
$MaxSecPerTick = 500

# Querying the Security log for "records newer than N" makes Windows scan the whole log every
# time (it cannot stop early), which took 10-30 s on a big log and froze the panel. A
# subscription instead gets each new event pushed once, as Windows writes it.
if (-not ('AuditPulseSecLog' -as [type])) {
    Add-Type -ReferencedAssemblies System.Core -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
public sealed class AuditPulseSecLog : IDisposable {
    public readonly ConcurrentQueue<EventRecord> Queue = new ConcurrentQueue<EventRecord>();
    public volatile string Error;
    private readonly EventLogWatcher w;
    public AuditPulseSecLog() {
        var q = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663 or EventID=4670 or EventID=4656)]]");
        w = new EventLogWatcher(q, null, false);
        w.EventRecordWritten += (s, e) => {
            if (e.EventException != null) { Error = e.EventException.Message; return; }
            if (e.EventRecord == null) return;
            if (Queue.Count > 100000) { e.EventRecord.Dispose(); Error = "queue full"; return; }
            Queue.Enqueue(e.EventRecord);
        };
        w.Enabled = true;
    }
    public void Dispose() { w.Enabled = false; w.Dispose(); }
}
'@
}

function Start-SecLog {
    try { $script:SecLog = New-Object AuditPulseSecLog; $script:SecStatus = 'ok' }
    catch { $script:SecStatus = 'unavailable'; Write-Log "[security] Security loguna abunə alınmadı: $($_.Exception.Message)" }
}

function Remember-Sec([string]$Path, $Info) {
    $k = $Path.ToLowerInvariant()
    if (-not $script:SecByPath.ContainsKey($k)) { $script:SecByPath[$k] = New-Object System.Collections.Generic.List[object] }
    $script:SecByPath[$k].Add($Info)
}

function Find-Sec([string]$Path, [double]$Ts) {
    $k = $Path.ToLowerInvariant()
    if (-not $script:SecByPath.ContainsKey($k)) { return $null }
    $best = $null; $gap = 6.0
    foreach ($s in $script:SecByPath[$k]) { $g = [Math]::Abs($s.ts - $Ts); if ($g -lt $gap) { $gap = $g; $best = $s } }
    return $best
}

function Get-SidName([string]$Sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { return $Sid }
}

function Get-Short([string]$Account) { if ($Account -match '\\') { return $Account.Split('\')[-1] } return $Account }

function Read-SecurityLog {
    if (-not $script:SecLog) { return }
    if ($script:SecLog.Error) { Write-Log "[security] $($script:SecLog.Error)"; $script:SecLog.Error = $null }
    # Take at most a batch per tick so a burst of events never keeps the panel waiting.
    $events = New-Object System.Collections.Generic.List[object]
    $ev = $null
    while ($events.Count -lt $MaxSecPerTick -and $script:SecLog.Queue.TryDequeue([ref]$ev)) { $events.Add($ev) }
    foreach ($ev in $events) {
      try {
        $d = @{}
        foreach ($n in ([xml]$ev.ToXml()).Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
        $path = $d['ObjectName']
        if (-not $path -or -not (Get-WatchKey $path)) { continue }
        $user = if ($d['SubjectUserName']) { $d['SubjectUserName'] } else { $null }
        $exe = $d['ProcessName']
        $ts = [DateTimeOffset]::new($ev.TimeCreated).ToUnixTimeMilliseconds() / 1000.0
        $failed = ($ev.Keywords -band 0x10000000000000) -ne 0
        if ($ev.Id -eq 4656 -and $failed) {
            Add-AuditEvent @{ ts = $ts; action = 'modify'; ftype = $(if (Test-Path -LiteralPath $path -PathType Container) { 'dir' } else { 'file' })
                path = $path; path2 = $null; success = 0; auser = $user; euser = $user; exe = $exe; comm = $(if ($exe) { Split-Path -Leaf $exe } else { $null })
                cmd = $null; tty = $null; watch = (Get-WatchKey $path); hidden = [int](Test-HiddenPath $path)
                old_mode = $null; new_mode = $null; old_owner = $null; new_owner = $null; sd_old = $null; sd_new = $null }
        } elseif ($ev.Id -eq 4670) {
            $oldSd = $d['OldSd']; $newSd = $d['NewSd']
            $oldOwner = if ($oldSd -match '^O:([^:]+?)(G:|D:|S:|$)') { Get-Short (Get-SidName $Matches[1]) } else { $null }
            $newOwner = if ($newSd -match '^O:([^:]+?)(G:|D:|S:|$)') { Get-Short (Get-SidName $Matches[1]) } else { $null }
            $action = if ($oldOwner -and $newOwner -and $oldOwner -ne $newOwner) { 'chown' } else { 'chmod' }
            Add-AuditEvent @{ ts = $ts; action = $action; ftype = $(if (Test-Path -LiteralPath $path -PathType Container) { 'dir' } else { 'file' })
                path = $path; path2 = $null; success = 1; auser = $user; euser = $user; exe = $exe; comm = $(if ($exe) { Split-Path -Leaf $exe } else { $null })
                cmd = $null; tty = $null; watch = (Get-WatchKey $path); hidden = [int](Test-HiddenPath $path)
                old_mode = $null; new_mode = $null; old_owner = $oldOwner; new_owner = $newOwner; sd_old = $oldSd; sd_new = $newSd }
        } elseif ($ev.Id -eq 4663 -and -not $failed) {
            Remember-Sec $path @{ ts = $ts; user = $user; exe = $exe }
        }
      } finally { $ev.Dispose() }
    }
    # forget old facts
    $cut = (Get-UnixNow) - 120
    foreach ($k in @($script:SecByPath.Keys)) {
        $list = $script:SecByPath[$k]; $list.RemoveAll({ param($x) $x.ts -lt $cut }) | Out-Null
        if ($list.Count -eq 0) { $script:SecByPath.Remove($k) }
    }
}

# ---------------------------------------------------------- file watchers

$script:Watchers = @()
$script:Pending = New-Object System.Collections.Generic.List[object]
$script:Recent = @{}  # "action|path" -> ts, to merge bursts of identical notifications

# FileSystemWatcher callbacks run on thread-pool threads. PowerShell's own event queue is not
# pumped while the main loop waits for HTTP requests, so a tiny C# class collects the
# notifications in a thread-safe queue that the loop drains.
if (-not ('AuditPulseWatcher' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Concurrent;
public sealed class AuditPulseWatcher : IDisposable {
    public readonly ConcurrentQueue<string[]> Queue = new ConcurrentQueue<string[]>();
    private readonly FileSystemWatcher w;
    public AuditPulseWatcher(string path) {
        w = new FileSystemWatcher(path);
        w.IncludeSubdirectories = true;
        w.InternalBufferSize = 65536;
        w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Security;
        w.Created += (s, e) => Queue.Enqueue(new string[] { "Created", e.FullPath, null });
        w.Deleted += (s, e) => Queue.Enqueue(new string[] { "Deleted", e.FullPath, null });
        w.Changed += (s, e) => Queue.Enqueue(new string[] { "Changed", e.FullPath, null });
        w.Renamed += (s, e) => Queue.Enqueue(new string[] { "Renamed", e.FullPath, e.OldFullPath });
        w.Error += (s, e) => Queue.Enqueue(new string[] { "Error", path, null });
        w.EnableRaisingEvents = true;
    }
    public void Dispose() { w.EnableRaisingEvents = false; w.Dispose(); }
}
'@
}

function Start-Watchers {
    foreach ($w in $script:Watchers) { $w.Dispose() }
    $script:Watchers = @()
    foreach ($f in $script:Config.folders) {
        if (-not (Test-Path -LiteralPath $f -PathType Container)) { Write-Log "[watch] qovluq tapılmadı: $f"; continue }
        $script:Watchers += New-Object AuditPulseWatcher($f)
    }
}

function Collect-FsEvents {
    foreach ($w in $script:Watchers) {
        $item = $null
        while ($w.Queue.TryDequeue([ref]$item)) {
            if ($item[0] -eq 'Error') { Write-Log "[watch] bufer doldu, bəzi hadisələr itə bilər: $($item[1])"; continue }
            $script:Pending.Add(@{ seen = (Get-UnixNow); type = $item[0]; path = $item[1]; old = $item[2] })
        }
    }
}

function Flush-Pending {
    $now = Get-UnixNow
    $ready = @($script:Pending | Where-Object { $now - $_.seen -ge 2.5 })  # wait so the Security log can catch up
    foreach ($p in $ready) { [void]$script:Pending.Remove($p) }
    foreach ($p in $ready) {
        $path = $p.path
        $isDir = Test-Path -LiteralPath $path -PathType Container
        $action = switch ($p.type) { 'Created' { 'create' } 'Deleted' { 'delete' } 'Renamed' { 'rename' } default { 'modify' } }
        if ($action -eq 'modify' -and $isDir) { continue }  # a folder "changes" whenever its contents do
        $key = "$action|$($path.ToLowerInvariant())"
        if ($script:Recent.ContainsKey($key) -and $now - $script:Recent[$key] -lt 3) { continue }
        if ($action -eq 'modify' -and $script:Recent.ContainsKey("create|$($path.ToLowerInvariant())") -and $now - $script:Recent["create|$($path.ToLowerInvariant())"] -lt 3) { continue }
        $script:Recent[$key] = $now
        $sec = Find-Sec $(if ($p.old) { $p.old } else { $path }) $p.seen
        if (-not $sec -and $p.old) { $sec = Find-Sec $path $p.seen }
        # Creating and deleting are often checked against the folder (AddFile / DeleteChild), so
        # Windows logs the parent folder instead of the file itself.
        if (-not $sec -and $action -in @('create', 'delete', 'rename')) { $sec = Find-Sec (Split-Path -Parent $(if ($p.old) { $p.old } else { $path })) $p.seen }
        $user = if ($sec) { $sec.user } else { $null }
        $exe = if ($sec) { $sec.exe } else { $null }
        Add-AuditEvent @{ ts = $p.seen; action = $action; ftype = $(if ($isDir) { 'dir' } else { 'file' })
            path = $(if ($p.old) { $p.old } else { $path }); path2 = $(if ($p.old) { $path } else { $null })
            success = 1; auser = $user; euser = $user; exe = $exe; comm = $(if ($exe) { Split-Path -Leaf $exe } else { $null })
            cmd = $null; tty = $null; watch = (Get-WatchKey $path); hidden = [int](Test-HiddenPath $path)
            old_mode = $null; new_mode = $null; old_owner = $null; new_owner = $null; sd_old = $null; sd_new = $null }
    }
    foreach ($k in @($script:Recent.Keys)) { if ($now - $script:Recent[$k] -gt 10) { $script:Recent.Remove($k) } }
}

# ------------------------------------------------------------------ queries

function Get-Arg($Query, [string]$Name) { $v = $Query[$Name]; if ($null -eq $v) { '' } else { [string]$v } }

function Find-Events($Query) {
    $after = Get-Arg $Query 'after_id'; $before = Get-Arg $Query 'before_id'
    $acts = @((Get-Arg $Query 'action').Split(',') | Where-Object { $_ })
    $user = Get-Arg $Query 'user'; $watch = Get-Arg $Query 'watch'; $q = Get-Arg $Query 'q'; $from = Get-Arg $Query 'from'
    $showHidden = (Get-Arg $Query 'hidden') -eq '1'
    $limitRaw = Get-Arg $Query 'limit'
    $limit = if ($limitRaw) { [Math]::Max(1, [Math]::Min([int]$limitRaw, 500)) } else { 100 }
    $afterN = if ($after) { [long]$after } else { $null }; $beforeN = if ($before) { [long]$before } else { $null }
    $fromN = if ($from) { [double]$from } else { $null }
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = $script:Events.Count - 1; $i -ge 0 -and $out.Count -lt $limit; $i--) {
        $e = $script:Events[$i]
        if ($null -ne $afterN -and $e.id -le $afterN) { break }
        if ($null -ne $beforeN -and $e.id -ge $beforeN) { continue }
        if (-not $showHidden -and $e.hidden) { continue }
        if ($acts.Count) {
            $ok = ($acts -contains 'denied' -and $e.success -eq 0) -or ($e.success -eq 1 -and $acts -contains $e.action)
            if (-not $ok) { continue }
        }
        if ($user) { $u = if ($e.auser) { $e.auser } else { 'sistem' }; if ($u -ne $user) { continue } }
        if ($watch -and $e.watch -ne $watch) { continue }
        if ($null -ne $fromN -and $e.ts -lt $fromN) { continue }
        if ($q -and -not ("$($e.path) $($e.path2) $($e.exe)".IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0)) { continue }
        $out.Add($e)
    }
    return , $out.ToArray()
}

function Get-Stats($Query) {
    $showHidden = (Get-Arg $Query 'hidden') -eq '1'
    $since = (Get-UnixNow) - 86400
    $by = @{}; $denied = 0; $total = 0; $users = @{}; $hours = @{}; $paths = @{}
    foreach ($e in $script:Events) {
        if (-not $showHidden -and $e.hidden) { continue }
        $total++
        if ($e.success -eq 0) { $denied++ } else { $by[$e.action] = 1 + [int]$by[$e.action] }
        $u = if ($e.auser) { $e.auser } else { 'sistem' }; $users[$u] = 1 + [int]$users[$u]
        if ($e.ts -ge $since) {
            $h = [int][Math]::Floor($e.ts / 3600); $hours[$h] = 1 + [int]$hours[$h]
            $paths[$e.path] = 1 + [int]$paths[$e.path]
        }
    }
    @{ total = $total; by_action = $by; denied = $denied; now = (Get-UnixNow)
       users = @($users.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { @{ user = $_.Key; n = $_.Value } })
       hours = @($hours.GetEnumerator() | ForEach-Object { @{ h = $_.Key; n = $_.Value } })
       top_paths = @($paths.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 6 | ForEach-Object { @{ path = $_.Key; n = $_.Value } }) }
}

function Get-Meta {
    $cur = @($script:Config.folders)
    $sugg = @($Suggested | Where-Object { (Test-Path -LiteralPath $_ -PathType Container) } | ForEach-Object { (Get-Item -LiteralPath $_ -Force).FullName.TrimEnd('\') } |
        Where-Object { $s = $_; -not ($cur | Where-Object { (Test-Inside $s $_) -or (Test-Inside $_ $s) }) } | Select-Object -Unique)
    @{ host = $env:COMPUTERNAME; platform = 'windows'; security_log = $script:SecStatus
       watched = @($cur | ForEach-Object { @{ dir = $_; key = (Get-FolderKey $_) } })
       can_edit = [bool]$script:Config.passwordHash; suggestions = $sugg; max_watches = $MaxWatches }
}

function Change-Watch([string]$Action, [string]$Raw) {
    $cur = @($script:Config.folders)
    if ($Action -eq 'add') {
        $path = Resolve-NewFolder $Raw $cur
        Set-FolderAudit $path $true
        $script:Config.folders = @($cur + $path)
    } elseif ($Action -eq 'remove') {
        $path = $cur | Where-Object { $_ -ieq $Raw } | Select-Object -First 1
        if (-not $path) { throw [ArgumentException]'Bu qovluq izlənmir' }
        try { Set-FolderAudit $path $false } catch { Write-Log "[watch] audit qaydası silinmədi: $path ($($_.Exception.Message))" }
        $script:Config.folders = @($cur | Where-Object { $_ -ine $path })
    } else { throw [ArgumentException]'invalid request' }
    Save-Config $script:Config
    Start-Watchers
    Write-Log "[watch] $Action $path"
    return $path
}

# --------------------------------------------------------------------- HTTP

$script:Fails = @{}

function Test-HostAllowed([string]$HostHeader) {
    if (-not $HostHeader) { return $false }
    $name = $HostHeader.ToLowerInvariant()
    if ($name.StartsWith('[')) { $name = $name.Substring(1).Split(']')[0] } elseif ($name.Split(':').Count -eq 2) { $name = $name.Split(':')[0] }
    $allowed = @('127.0.0.1', 'localhost', '::1') + @($script:Config.allowedHosts | ForEach-Object { "$_".ToLowerInvariant() })
    return $allowed -contains $name
}

function Send($Ctx, [int]$Code, [byte[]]$Body, [string]$Type, [hashtable]$Extra = @{}) {
    $r = $Ctx.Response
    $r.StatusCode = $Code; $r.ContentType = $Type
    $r.Headers['Cache-Control'] = 'no-store'
    $r.Headers['X-Content-Type-Options'] = 'nosniff'
    $r.Headers['X-Frame-Options'] = 'DENY'
    $r.Headers['Referrer-Policy'] = 'no-referrer'
    $r.Headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    foreach ($k in $Extra.Keys) { $r.Headers[$k] = $Extra[$k] }
    $r.ContentLength64 = $Body.Length
    $r.OutputStream.Write($Body, 0, $Body.Length)
    $r.OutputStream.Close()
}

function Send-Json($Ctx, [int]$Code, $Data) {
    Send $Ctx $Code ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Data -Depth 6 -Compress))) 'application/json; charset=utf-8'
}

function Send-Text($Ctx, [int]$Code, [string]$Text, [hashtable]$Extra = @{}) {
    Send $Ctx $Code ([Text.Encoding]::UTF8.GetBytes($Text)) 'text/plain; charset=utf-8' $Extra
}

function Test-Gate($Ctx) {
    $req = $Ctx.Request
    if (-not (Test-HostAllowed $req.Headers['Host'])) { Send-Text $Ctx 421 'unknown host'; return $false }
    if (-not $script:Config.passwordHash) { return $true }
    $ip = $req.RemoteEndPoint.Address.ToString(); $now = Get-UnixNow
    $list = @($script:Fails[$ip] | Where-Object { $_ -gt $now - $AuthWindow })
    $script:Fails[$ip] = $list
    if ($list.Count -ge $AuthMaxFails) { Send-Text $Ctx 429 'too many failed logins, try again in 15 minutes' @{ 'Retry-After' = "$AuthWindow" }; return $false }
    $auth = $req.Headers['Authorization']
    if ($auth -and $auth.StartsWith('Basic ')) {
        try { $pair = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($auth.Substring(6))) } catch { $pair = '' }
        $given = if ($pair.Contains(':')) { $pair.Substring($pair.IndexOf(':') + 1) } else { '' }
        if (Test-Password $given $script:Config.passwordHash) { return $true }
        $script:Fails[$ip] = @($list + $now)
    }
    Send-Text $Ctx 401 'password required' @{ 'WWW-Authenticate' = 'Basic realm="AuditPulse"' }
    return $false
}

function Handle($Ctx) {
    $req = $Ctx.Request
    if (-not (Test-Gate $Ctx)) { return }
    $path = $req.Url.AbsolutePath
    $query = @{}; foreach ($k in $req.QueryString.AllKeys) { if ($k) { $query[$k] = $req.QueryString[$k] } }
    try {
        if ($req.HttpMethod -eq 'GET') {
            switch ($path) {
                '/' { Send $Ctx 200 ([IO.File]::ReadAllBytes((Join-Path $WebDir 'index.html'))) 'text/html; charset=utf-8'; return }
                '/index.html' { Send $Ctx 200 ([IO.File]::ReadAllBytes((Join-Path $WebDir 'index.html'))) 'text/html; charset=utf-8'; return }
                '/api/events' { Send-Json $Ctx 200 (Find-Events $query); return }
                '/api/stats' { Send-Json $Ctx 200 (Get-Stats $query); return }
                '/api/meta' { Send-Json $Ctx 200 (Get-Meta); return }
            }
            Send-Text $Ctx 404 'not found'; return
        }
        if ($req.HttpMethod -eq 'POST' -and $path -eq '/api/watches') {
            if (-not $script:Config.passwordHash) { Send-Json $Ctx 403 @{ error = 'Qovluqları paneldən dəyişmək üçün əvvəlcə parol qoyun: Install-AuditPulse.ps1 -SetPassword' }; return }
            $origin = $req.Headers['Origin']
            $originOk = (-not $origin) -or ((Test-HostAllowed ([Uri]$origin).Authority) -and ([Uri]$origin).Authority -eq $req.Headers['Host'])
            if ($req.Headers['X-AuditPulse'] -ne '1' -or -not $originOk) { Send-Json $Ctx 403 @{ error = 'forbidden' }; return }
            if ($req.ContentLength64 -gt 2048 -or -not "$($req.ContentType)".StartsWith('application/json')) { Send-Json $Ctx 400 @{ error = 'invalid request' }; return }
            $reader = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
            try { $body = $reader.ReadToEnd() | ConvertFrom-Json } catch { Send-Json $Ctx 400 @{ error = 'invalid request' }; return }
            try {
                $done = Change-Watch ([string]$body.action) ([string]$body.path)
                Send-Json $Ctx 200 @{ ok = $true; path = $done }
            } catch [ArgumentException] {
                Send-Json $Ctx 400 @{ error = $_.Exception.Message }
            } catch {
                Write-Log "[watch] alınmadı: $($_.Exception.Message)"
                Send-Json $Ctx 500 @{ error = 'Audit qaydası qoyulmadı. Servis admin (SYSTEM) kimi işləyirmi? Ətraflı: ' + $LogFile }
            }
            return
        }
        Send-Text $Ctx 404 'not found'
    } catch {
        Write-Log "[http] xəta: $($_.Exception.Message)"
        try { Send-Json $Ctx 400 @{ error = 'invalid request' } } catch { }
    }
}

# --------------------------------------------------------------------- main

if ($LibraryOnly) { return }

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$script:Config = Get-Config
if ($Port) { $script:Config.port = $Port }
if ($script:Config.host -notin @('127.0.0.1', 'localhost') -and -not $script:Config.passwordHash) {
    throw "Panel şəbəkəyə açıqdır ($($script:Config.host)), amma parol yoxdur. Əvvəlcə Install-AuditPulse.ps1 -SetPassword işlədin."
}
Load-Events
Start-Watchers
Start-SecLog

$listener = New-Object System.Net.HttpListener
$hostName = if ($script:Config.host -in @('127.0.0.1', 'localhost')) { $script:Config.host } else { '+' }
$listener.Prefixes.Add("http://${hostName}:$($script:Config.port)/")
if ($hostName -eq '127.0.0.1') { $listener.Prefixes.Add("http://localhost:$($script:Config.port)/") }
$listener.Start()
Write-Log "AuditPulse işləyir: http://localhost:$($script:Config.port)  (izlənir: $($script:Config.folders -join ', '))"

$lastErr = ''
try {
    while ($listener.IsListening) {
        $task = $listener.GetContextAsync()
        while (-not $task.Wait(250)) {
            # One bad event or path must not stop the whole service: log it and keep going.
            try {
                Collect-FsEvents
                Read-SecurityLog
                Flush-Pending
            } catch {
                $msg = "$($_.Exception.Message) @ $($_.InvocationInfo.ScriptLineNumber)"
                if ($msg -ne $lastErr) { Write-Log "[loop] xəta (servis davam edir): $msg"; $lastErr = $msg }
            }
        }
        Handle $task.Result
    }
} catch {
    Write-Log "[fatal] servis dayandı: $($_.Exception.Message) @ $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
} finally {
    $listener.Stop()
    foreach ($w in $script:Watchers) { $w.Dispose() }
    if ($script:SecLog) { $script:SecLog.Dispose() }
}
