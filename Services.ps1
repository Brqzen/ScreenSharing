$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  WARNING: This script must be run as Administrator." -ForegroundColor Yellow
    Write-Host "  Choose 'Run as administrator', then try again." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Press Enter to exit"
    exit 1
}

$Targets = @(
    @{ Name="SysMain";     Kind="Service"; Friendly="SysMain (Superfetch)" }
    @{ Name="PcaSvc";      Kind="Service"; Friendly="PcaSvc (Program Compatibility Assistant)" }
    @{ Name="DPS";         Kind="Service"; Friendly="DPS (Diagnostic Policy Service)" }
    @{ Name="EventLog";    Kind="Service"; Friendly="EventLog (Windows Event Log)" }
    @{ Name="Schedule";    Kind="Service"; Friendly="Schedule (Task Scheduler)" }
    @{ Name="WSearch";     Kind="Service"; Friendly="WSearch (Windows Search)" }
    @{ Name="Appinfo";     Kind="Service"; Friendly="Appinfo (Application Information)" }
    @{ Name="SSDPSRV";     Kind="Service"; Friendly="SSDPSRV (SSDP Discovery)" }
    @{ Name="CDPSvc";      Kind="Service"; Friendly="CDPSvc (Connected Devices Platform)" }
    @{ Name="DcomLaunch";  Kind="Service"; Friendly="DcomLaunch (DCOM Server Process Launcher)" }
    @{ Name="PlugPlay";    Kind="Service"; Friendly="PlugPlay (Plug and Play)" }
    @{ Name="DiagTrack";   Kind="Service"; Friendly="DiagTrack (Connected User Experiences and Telemetry)" }
    @{ Name="DusmSvc";     Kind="Service"; Friendly="DusmSvc (Data Usage)" }
    @{ Name="bam";         Kind="Driver";  Friendly="bam (Background Activity Moderator driver)" }
)

$Theme = [pscustomobject]@{
    Primary = "Cyan"
    Muted   = "DarkCyan"
    Warn    = "Yellow"
    Good    = "Green"
    Snow    = "*"
    Line    = ("-" * 44)
}

function Clear-ConsoleInputBuffer {
    try {
        while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }
    } catch {
    }
}

function Pause-ForEnter {
    Clear-ConsoleInputBuffer
    Write-Host ""
    Read-Host ("  {0} Press Enter to continue" -f $Theme.Snow)
}

function Show-Header {
    Write-Host ""
    Write-Host ("  {0}  Service Checker" -f $Theme.Snow) -ForegroundColor $Theme.Primary
    Write-Host ("  {0}" -f $Theme.Line) -ForegroundColor $Theme.Muted
    Write-Host ""
}

function Get-StatusSnapshot {
    param([Parameter(Mandatory)] $Targets)

    $serviceNames = @($Targets | Where-Object Kind -eq "Service" | ForEach-Object Name)
    $driverNames  = @($Targets | Where-Object Kind -eq "Driver"  | ForEach-Object Name)

    $svcMap = @{}
    if ($serviceNames.Count -gt 0) {
        $filter = ($serviceNames | ForEach-Object { "Name='$($_)'" }) -join " OR "
        foreach ($svc in (Get-CimInstance -ClassName Win32_Service -Filter $filter -ErrorAction SilentlyContinue)) {
            $svcMap[$svc.Name] = $svc
        }
    }

    $drvMap = @{}
    if ($driverNames.Count -gt 0) {
        $filter = ($driverNames | ForEach-Object { "Name='$($_)'" }) -join " OR "
        foreach ($drv in (Get-CimInstance -ClassName Win32_SystemDriver -Filter $filter -ErrorAction SilentlyContinue)) {
            $drvMap[$drv.Name] = $drv
        }
    }

    return [pscustomobject]@{ Services = $svcMap; Drivers = $drvMap }
}

function Get-TargetRow {
    param(
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)] $Snapshot
    )

    if ($Target.Kind -eq "Service") {
        if (-not $Snapshot.Services.ContainsKey($Target.Name)) {
            return [pscustomobject]@{ Name=$Target.Name; Found=$false; Status="N/A"; StartMode="N/A" }
        }
        $svc = $Snapshot.Services[$Target.Name]
        return [pscustomobject]@{ Name=$Target.Name; Found=$true; Status=$svc.State; StartMode=$svc.StartMode }
    }

    if (-not $Snapshot.Drivers.ContainsKey($Target.Name)) {
        return [pscustomobject]@{ Name=$Target.Name; Found=$false; Status="N/A"; StartMode="N/A" }
    }
    $drv = $Snapshot.Drivers[$Target.Name]
    return [pscustomobject]@{ Name=$Target.Name; Found=$true; Status=$drv.State; StartMode=$drv.StartMode }
}

function Get-RegValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    try {
        return Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-ExtraChecks {
    $checks = [System.Collections.Generic.List[object]]::new()

    $sid = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { $null }
    $bamBase = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $bamSid  = if ($sid) { Join-Path $bamBase $sid } else { $null }
    $prot = $false
    try { if ((Get-Acl $bamBase -ErrorAction Stop).AreAccessRulesProtected) { $prot = $true } } catch {}
    if ($bamSid -and -not $prot) {
        try { if ((Get-Acl $bamSid -ErrorAction Stop).AreAccessRulesProtected) { $prot = $true } } catch {}
    }
    $checks.Add([pscustomobject]@{ Other = "BAM Inheritance";    Status = if ($prot) { "Terminated" } else { "Normal" } })

    $noRecentLM = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRecentDocsHistory"
    $noRecentCU = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRecentDocsHistory"
    $trackDocs  = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackDocs"
    $jumpOff = ($noRecentLM -eq 1) -or ($noRecentCU -eq 1) -or ($null -ne $trackDocs -and $trackDocs -eq 0)
    $checks.Add([pscustomobject]@{ Other = "JumpLists";          Status = if ($jumpOff) { "Disabled" } else { "Enabled" } })

    $wait = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control" "WaitToKillServiceTimeout"
    $ms = 5000
    if ($null -ne $wait) { [void][int]::TryParse($wait.ToString().Trim(), [ref]$ms) }
    $checks.Add([pscustomobject]@{ Other = "Service Threads";    Status = if ($ms -lt 5000) { "Terminated" } else { "Enabled" } })

    $dpsProc = $null
    try {
        $dpsSvc = Get-CimInstance Win32_Service -Filter "Name='DPS'" -ErrorAction SilentlyContinue
        if ($dpsSvc -and $dpsSvc.ProcessId -gt 0) { $dpsProc = Get-Process -Id $dpsSvc.ProcessId -ErrorAction SilentlyContinue }
    } catch {}
    $dpsRunning = $null -ne $dpsProc
    $checks.Add([pscustomobject]@{ Other = "DPS Tokens";         Status = if ($dpsRunning) { "Enabled" } else { "Disabled" } })

    $actFeed = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed"
    $checks.Add([pscustomobject]@{ Other = "Activities Cache";   Status = if ($actFeed -eq 0) { "Disabled" } else { "Enabled" } })

    $prefetch = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher"
    $checks.Add([pscustomobject]@{ Other = "EnablePrefetcher";   Status = if ($prefetch -eq 0) { "Disabled" } else { "Enabled" } })

    return $checks
}

function Set-RegValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [string] $Type = "DWord"
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction SilentlyContinue
}

function Remove-RegValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    try { Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop } catch {}
}

function Set-ExtraSettings {
    $sid = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { $null }
    $bamPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings")
    if ($sid) { $bamPaths += Join-Path $bamPaths[0] $sid }

    foreach ($p in $bamPaths) {
        try {
            $acl = Get-Acl -Path $p -ErrorAction Stop
            $acl.SetAccessRuleProtection($false, $false)
            Set-Acl -Path $p -AclObject $acl -ErrorAction SilentlyContinue
        } catch {}
    }
    Write-Host ("  {0} BAM Inheritance: Restored" -f $Theme.Snow) -ForegroundColor $Theme.Primary

    $polLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $polCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $advCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Remove-RegValue $polLM "NoRecentDocsHistory"
    Remove-RegValue $polCU "NoRecentDocsHistory"
    Set-RegValue $advCU "Start_TrackDocs" 1
    Write-Host ("  {0} JumpLists: Enabled" -f $Theme.Snow) -ForegroundColor $Theme.Primary

    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control" "WaitToKillServiceTimeout" "5000" -Type "String"
    Write-Host ("  {0} Service Threads: Enabled (5000ms)" -f $Theme.Snow) -ForegroundColor $Theme.Primary

    Write-Host ("  {0} DPS Tokens: Enabled (follows DPS service)" -f $Theme.Snow) -ForegroundColor $Theme.Primary

    Remove-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed"
    Write-Host ("  {0} Activities Cache: Enabled" -f $Theme.Snow) -ForegroundColor $Theme.Primary

    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 3
    Write-Host ("  {0} EnablePrefetcher: Enabled" -f $Theme.Snow) -ForegroundColor $Theme.Primary
}

function Set-TargetStartup {
    param([Parameter(Mandatory)] $Target)

    if ($Target.Kind -eq "Service") {
        if (-not (Get-Service -Name $Target.Name -ErrorAction SilentlyContinue)) {
            Write-Host ("  {0} Missing service: {1}" -f $Theme.Snow, $Target.Name) -ForegroundColor $Theme.Warn
            return
        }
        sc.exe config $Target.Name start= auto | Out-Null
        $svc = Get-Service -Name $Target.Name -ErrorAction SilentlyContinue
        if ($svc.Status -eq 'Running') { return }
        try { sc.exe start $Target.Name 2>&1 | Out-Null } catch {}
        for ($i = 0; $i -lt 5; $i++) {
            Start-Sleep -Milliseconds 1500
            $svc = Get-Service -Name $Target.Name -ErrorAction SilentlyContinue
            if ($svc.Status -eq 'Running') { return }
        }
        Write-Host ("  {0} Failed to start: {1}" -f $Theme.Snow, $Target.Friendly) -ForegroundColor $Theme.Warn
        return
    }

    sc.exe config $Target.Name start= auto | Out-Null
}

function Show-Menu {
    Write-Host ("  {0} Select an option:" -f $Theme.Snow) -ForegroundColor $Theme.Primary
    Write-Host ""
    Write-Host "    1 - Enable services" -ForegroundColor $Theme.Primary
    Write-Host "    2 - Check status" -ForegroundColor $Theme.Primary
    Write-Host "    0 - Exit" -ForegroundColor $Theme.Primary
    Write-Host ""
}

do {
    Clear-Host
    Show-Header
    Show-Menu

    Clear-ConsoleInputBuffer
    $choice = Read-Host "  Enter 0, 1, or 2"

    switch ($choice) {
        "1" {
            Clear-Host
            Show-Header
            foreach ($t in $Targets) {
                Write-Host ("  {0} Enabling {1}" -f $Theme.Snow, $t.Friendly) -ForegroundColor $Theme.Primary
                Set-TargetStartup -Target $t
            }
            Write-Host ""
            Set-ExtraSettings
            Write-Host ""
            Write-Host ("  {0} Done." -f $Theme.Snow) -ForegroundColor $Theme.Good
            Pause-ForEnter
        }
        "2" {
            Clear-Host
            Show-Header
            Write-Host ("  {0} Status / StartMode" -f $Theme.Snow) -ForegroundColor $Theme.Primary
            Write-Host ("  {0}" -f $Theme.Line) -ForegroundColor $Theme.Muted
            Write-Host ""

            $snapshot = Get-StatusSnapshot -Targets $Targets
            $rows = foreach ($t in $Targets) { Get-TargetRow -Target $t -Snapshot $snapshot }

            $tableText = ($rows | Sort-Object Name | Format-Table -AutoSize | Out-String).TrimEnd()
            foreach ($line in $tableText -split "`r?`n") {
                Write-Host ("  {0}" -f $line) -ForegroundColor $Theme.Primary
            }

            Write-Host ""
            Write-Host ("  {0} Other" -f $Theme.Snow) -ForegroundColor $Theme.Primary
            Write-Host ("  {0}" -f $Theme.Line) -ForegroundColor $Theme.Muted
            Write-Host ""

            $checks = Get-ExtraChecks
            $checksText = ($checks | Format-Table -AutoSize | Out-String).TrimEnd()
            foreach ($line in $checksText -split "`r?`n") {
                Write-Host ("  {0}" -f $line) -ForegroundColor $Theme.Primary
            }
            Pause-ForEnter
        }
        "0" { return }
        default {
            Write-Host ""
            Write-Host ("  {0} Invalid choice." -f $Theme.Snow) -ForegroundColor $Theme.Warn
            Pause-ForEnter
        }
    }
} while ($true)
