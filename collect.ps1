# Service Dashboard collector.
# Runs every 2 minutes as SYSTEM (scheduled task created by install.ps1) and writes
# facts the dashboard's own low-privilege account isn't allowed to read:
#   - listening ports with their program paths and services
#   - Windows Firewall rules and profiles
#   - failed and successful remote logons from the Security log
# It reads nothing the dashboard can write, and only writes to the "collected" folder.

param(
  [string]$OutDir = (Join-Path $PSScriptRoot 'collected'),
  [int]$Hours = 24
)

$ErrorActionPreference = 'Continue'
$errors = New-Object System.Collections.Generic.List[string]
$now = Get-Date

# ---------- processes and services ----------
$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
$svcByPid = @{}
Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object {
  $k = [int]$_.ProcessId
  if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = @() }
  $svcByPid[$k] += [string]$_.Name
}

function Describe-Process([int]$procId) {
  $p = $procs[$procId]
  [pscustomobject]@{
    process  = if ($procId -eq 4) { 'System' } elseif ($p) { [string]$p.Name } else { $null }
    path     = if ($p -and $p.ExecutablePath) { [string]$p.ExecutablePath } else { $null }
    services = @(if ($svcByPid.ContainsKey($procId)) { $svcByPid[$procId] })
  }
}

# ---------- listening ports ----------
$listeners = @()
try {
  foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
    $d = Describe-Process ([int]$c.OwningProcess)
    $listeners += [pscustomobject]@{ proto = 'TCP'; address = [string]$c.LocalAddress; port = [int]$c.LocalPort; pid = [int]$c.OwningProcess; process = $d.process; path = $d.path; services = $d.services }
  }
  # UDP below the ephemeral range only (above it is mostly short-lived client sockets)
  foreach ($u in Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.LocalPort -lt 49152 }) {
    $d = Describe-Process ([int]$u.OwningProcess)
    $listeners += [pscustomobject]@{ proto = 'UDP'; address = [string]$u.LocalAddress; port = [int]$u.LocalPort; pid = [int]$u.OwningProcess; process = $d.process; path = $d.path; services = $d.services }
  }
} catch { $errors.Add("Listening ports: $($_.Exception.Message)") }

# ---------- firewall ----------
$firewall = $null
try {
  $active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
    switch ([string]$_.NetworkCategory) { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } }
  } | Select-Object -Unique)
  if ($active.Count -eq 0) { $active = @('Public') }

  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True'); defaultInbound = [string]$_.DefaultInboundAction }
  })

  $pf = @{}; Get-NetFirewallPortFilter        -PolicyStore ActiveStore -All | ForEach-Object { $pf[[string]$_.InstanceID] = $_ }
  $af = @{}; Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All | ForEach-Object { $af[[string]$_.InstanceID] = $_ }
  $sf = @{}; Get-NetFirewallServiceFilter     -PolicyStore ActiveStore -All | ForEach-Object { $sf[[string]$_.InstanceID] = $_ }
  $ad = @{}; Get-NetFirewallAddressFilter     -PolicyStore ActiveStore -All | ForEach-Object { $ad[[string]$_.InstanceID] = $_ }
  $ifl = @{}; Get-NetFirewallInterfaceFilter    -PolicyStore ActiveStore -All -ErrorAction SilentlyContinue | ForEach-Object { $ifl[[string]$_.InstanceID] = $_ }
  $ift = @{}; Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore -All -ErrorAction SilentlyContinue | ForEach-Object { $ift[[string]$_.InstanceID] = $_ }

  # Interfaces that carry public traffic, so interface-limited rules can be judged correctly
  $publicInterfaces = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object {
      $_.IPAddress -notmatch '^(127\.|169\.254\.|::1$|fe80:)'
    } | Select-Object -ExpandProperty InterfaceAlias -Unique | ForEach-Object {
      $adapter = Get-NetAdapter -Name $_ -ErrorAction SilentlyContinue
      $media = if ($adapter) { [string]$adapter.PhysicalMediaType } else { '' }
      [pscustomobject]@{ alias = [string]$_; type = if ($media -match '802\.11|Wireless|Wi-?Fi') { 'Wireless' } else { 'Wired' } }
    })

  $rules = @(foreach ($r in Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True) {
    $id = if ($r.InstanceID) { [string]$r.InstanceID } else { [string]$r.Name }
    $p = $pf[$id]; $a = $af[$id]; $s = $sf[$id]; $addr = $ad[$id]; $i = $ifl[$id]; $t = $ift[$id]
    $program = if ($a -and $a.Program) { [string]$a.Program } else { 'Any' }
    if ($program -ne 'Any' -and $program -ne 'System') { $program = [Environment]::ExpandEnvironmentVariables($program) }
    [pscustomobject]@{
      name     = [string]$r.DisplayName
      action   = [string]$r.Action
      profile  = [string]$r.Profile
      protocol = if ($p) { [string]$p.Protocol } else { 'Any' }
      ports    = @(if ($p) { $p.LocalPort | ForEach-Object { [string]$_ } } else { 'Any' })
      program  = $program
      service  = if ($s -and $s.Service) { [string]$s.Service } else { 'Any' }
      remote   = @(if ($addr) { $addr.RemoteAddress | ForEach-Object { [string]$_ } } else { 'Any' })
      # Rules for packaged (Store-style) apps only apply inside that app's sandbox
      package  = if ($a -and $a.Package) { [string]$a.Package } else { '' }
      interfaces    = @(if ($i -and $i.InterfaceAlias) { $i.InterfaceAlias | ForEach-Object { [string]$_ } } else { 'Any' })
      interfaceType = if ($t -and $t.InterfaceType) { [string]$t.InterfaceType } else { 'Any' }
      owner    = if ($r.Owner) { [string]$r.Owner } else { '' }
    }
  })

  $firewall = [pscustomobject]@{ activeProfiles = $active; profiles = $profiles; publicInterfaces = $publicInterfaces; rules = $rules }
} catch { $errors.Add("Firewall: $($_.Exception.Message)") }

# ---------- logons ----------
$logons = $null
try {
  $ms = [int]($Hours * 3600 * 1000)

  $failed = @(Get-WinEvent -LogName Security -MaxEvents 10000 -ErrorAction SilentlyContinue `
      -FilterXPath "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]]" | ForEach-Object {
    [pscustomobject]@{
      t    = $_.TimeCreated.ToUniversalTime().ToString('o')
      user = [string]$_.Properties[5].Value
      type = [int]$_.Properties[10].Value
      ip   = [string]$_.Properties[19].Value
    }
  })

  $xpathOk = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]"
  $success = @(Get-WinEvent -LogName Security -MaxEvents 5000 -ErrorAction SilentlyContinue -FilterXPath $xpathOk | ForEach-Object {
    $ip = [string]$_.Properties[18].Value
    $user = [string]$_.Properties[5].Value
    $type = [int]$_.Properties[8].Value
    # Skip local/loopback network logons, machine accounts and anonymous sessions
    if ($type -eq 3 -and ($ip -in @('-', '', '127.0.0.1', '::1'))) { return }
    if ($user -like '*$' -or $user -eq 'ANONYMOUS LOGON') { return }
    [pscustomobject]@{ t = $_.TimeCreated.ToUniversalTime().ToString('o'); user = $user; type = $type; ip = $ip }
  } | Select-Object -First 100)

  $lockouts = @(Get-WinEvent -LogName Security -ErrorAction SilentlyContinue `
      -FilterXPath "*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= $ms]]]").Count

  $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
  # Logon subcategory GUID, so this works on any Windows language
  $audit = (auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>$null) -join ' '

  $logons = [pscustomobject]@{
    failed           = $failed
    success          = $success
    lockouts         = $lockouts
    oldestEvent      = if ($oldest) { $oldest.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
    failureAuditing  = if ($audit) { [bool]($audit -match 'Failure') } else { $null }
  }
} catch { $errors.Add("Security log: $($_.Exception.Message)") }

# ---------- maintenance ----------
# Reboot state is a registry read. The Windows Update search is slow, so its
# result is cached for 6 hours in updates.json and copied into each report.
$maintenance = $null
try {
  $reboot = $false
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot = $true }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot = $true }
  if (-not $reboot) {
    $pendingRename = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pendingRename -and $pendingRename.PendingFileRenameOperations) { $reboot = $true }
  }

  New-Item -ItemType Directory $OutDir -Force | Out-Null
  $cacheFile = Join-Path $OutDir 'updates.json'
  $updates = $null
  if (Test-Path $cacheFile) {
    try {
      $cached = Get-Content $cacheFile -Raw | ConvertFrom-Json
      $checked = [datetimeoffset]::Parse([string]$cached.checkedAt)
      if ((([datetimeoffset]::UtcNow) - $checked).TotalHours -lt 6) { $updates = $cached }
    } catch { }
  }

  if (-not $updates) {
    $updates = [pscustomobject]@{ count = $null; titles = @(); checkedAt = [datetimeoffset]::UtcNow.ToString('o'); error = $null }
    $rs = $null
    $ps = $null
    try {
      $rs = [runspacefactory]::CreateRunspace()
      $rs.ApartmentState = 'STA'
      $rs.Open()
      $ps = [powershell]::Create()
      $ps.Runspace = $rs
      [void]$ps.AddScript({
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $titles = New-Object System.Collections.Generic.List[string]
        foreach ($u in $found.Updates) {
          if ($titles.Count -ge 8) { break }
          [void]$titles.Add([string]$u.Title)
        }
        [pscustomobject]@{ count = [int]$found.Updates.Count; titles = @($titles) }
      })
      $handle = $ps.BeginInvoke()
      if (-not $handle.AsyncWaitHandle.WaitOne(45000)) {
        [void]$ps.Stop()
        $updates.error = 'Update search took too long and was skipped. It will be tried again on a later run.'
      } else {
        $found = @($ps.EndInvoke($handle))
        if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0) {
          $updates.error = [string]$ps.Streams.Error[0].Exception.Message
        } elseif ($found.Count -gt 0 -and $null -ne $found[0].count) {
          $updates.count = [int]$found[0].count
          $updates.titles = @($found[0].titles)
        } else {
          $updates.count = 0
        }
      }
    } catch {
      $updates.error = $_.Exception.Message
    } finally {
      if ($ps) { $ps.Dispose() }
      if ($rs) { $rs.Close(); $rs.Dispose() }
    }
    $cacheJson = ConvertTo-Json -InputObject $updates -Depth 4 -Compress
    [IO.File]::WriteAllText($cacheFile, $cacheJson, (New-Object System.Text.UTF8Encoding $false))
  }

  $maintenance = [pscustomobject]@{ rebootPending = [bool]$reboot; updates = $updates }
} catch { $errors.Add("Maintenance: $($_.Exception.Message)") }

# ---------- write atomically ----------
$result = [pscustomobject]@{
  generatedAt = $now.ToUniversalTime().ToString('o')
  hours       = $Hours
  listeners   = $listeners
  firewall    = $firewall
  logons      = $logons
  maintenance = $maintenance
  errors      = @($errors)
}

New-Item -ItemType Directory $OutDir -Force | Out-Null
$json = ConvertTo-Json -InputObject $result -Depth 6 -Compress
$tmp = Join-Path $OutDir 'security.json.tmp'
[IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding $false))
Move-Item $tmp (Join-Path $OutDir 'security.json') -Force
