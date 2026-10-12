#Requires -RunAsAdministrator
# Installs the service dashboard as a locked-down Windows service.
# Safe to re-run: it recreates the service and re-applies permissions
# (re-run it after adding services or log paths to config.json).

param(
  [string]$Dir  = "C:\apps\svcdash",
  [string]$Node = "C:\Program Files\nodejs\node.exe"
)

$ErrorActionPreference = 'Stop'
$svc = 'svcdash'

if (-not (Test-Path "$Dir\server.js")) { throw "server.js not found in $Dir. Copy the svcdash folder there first." }
if (-not (Test-Path $Node))            { throw "Node not found at $Node. Pass -Node with the right path." }
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) { throw "nssm is not on PATH." }

try {
  $config = Get-Content "$Dir\config.json" -Raw | ConvertFrom-Json
} catch {
  throw "config.json is not valid JSON. Use forward slashes in paths (C:/apps/...). Details: $($_.Exception.Message)"
}

New-Item -ItemType Directory "$Dir\logs" -Force | Out-Null

# --- (Re)create the service ---
if (Get-Service $svc -ErrorAction SilentlyContinue) {
  Stop-Service $svc -ErrorAction SilentlyContinue
  nssm remove $svc confirm | Out-Null
  Start-Sleep 2
}

nssm install $svc $Node "server.js" | Out-Null
nssm set $svc DisplayName "Service Dashboard" | Out-Null
nssm set $svc AppDirectory $Dir | Out-Null
nssm set $svc AppStdout "$Dir\logs\out.log" | Out-Null
nssm set $svc AppStderr "$Dir\logs\err.log" | Out-Null
nssm set $svc AppRotateFiles 1 | Out-Null
nssm set $svc AppRotateOnline 1 | Out-Null
nssm set $svc AppRotateBytes 5242880 | Out-Null
nssm set $svc Start SERVICE_DELAYED_AUTO_START | Out-Null
nssm set $svc AppExit Default Restart | Out-Null
nssm set $svc AppRestartDelay 5000 | Out-Null

# Run as its own virtual account, not Administrator or SYSTEM
sc.exe config $svc obj= "NT SERVICE\$svc" | Out-Null

# --- File permissions: read its own code, write only its own logs ---
icacls $Dir         /grant "NT SERVICE\${svc}:(OI)(CI)RX" | Out-Null
icacls "$Dir\logs"  /grant "NT SERVICE\${svc}:(OI)(CI)M"  | Out-Null
# config.json decides what the dashboard may control, so the dashboard itself must not be able to edit it
icacls "$Dir\config.json" /inheritance:r /grant "Administrators:F" "SYSTEM:F" "NT SERVICE\${svc}:R" | Out-Null

# state: history and site checks, written by the dashboard
New-Item -ItemType Directory "$Dir\state" -Force | Out-Null
icacls "$Dir\state" /grant "NT SERVICE\${svc}:(OI)(CI)M" | Out-Null

# collected: written only by the SYSTEM collector task; the dashboard can only read it
New-Item -ItemType Directory "$Dir\collected" -Force | Out-Null
icacls "$Dir\collected" /inheritance:r /grant "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "NT SERVICE\${svc}:(OI)(CI)RX" | Out-Null

# collect.ps1 runs as SYSTEM, so only administrators may change it
icacls "$Dir\collect.ps1" /inheritance:r /grant "Administrators:F" "SYSTEM:F" "NT SERVICE\${svc}:R" | Out-Null

"`n--- Log access ---"
$logPaths = @()
foreach ($s in $config.services) { $logPaths += @($s.logs) }
if ($config.attackSources) {
  if ($config.attackSources.mariadbLog) { $logPaths += $config.attackSources.mariadbLog }
  if ($config.attackSources.caddyLogs)  { $logPaths += $config.attackSources.caddyLogs }
}
foreach ($p in ($logPaths | Select-Object -Unique)) {
    $win = $p -replace '/', '\'
    if (Test-Path $win -PathType Container) {
      icacls $win /grant "NT SERVICE\${svc}:(OI)(CI)RX" | Out-Null
      "Read access: $win"
    } elseif (Test-Path $win -PathType Leaf) {
      icacls $win /grant "NT SERVICE\${svc}:R" | Out-Null
      "Read access: $win"
    } else {
      Write-Warning "Not found, fix this path in config.json: $win"
    }
}

# --- Service control permissions ---
# Adds one entry to each controllable service's permissions so NT SERVICE\svcdash can
# query, start, stop and restart it. Nothing else on the system is affected.
"`n--- Service control ---"
$sidLine = (sc.exe showsid $svc) | Select-String 'SERVICE SID:'
$sid = ($sidLine.ToString() -split ':\s*', 2)[1].Trim()
$rights = 'CCLCSWRPWPDTLOCRRC'   # query config/status, list dependents, start, stop, pause, interrogate, read
$self = if ($config.self) { $config.self } else { 'svcdash' }

foreach ($s in $config.services) {
  $name = $s.name
  if ($name -ieq $self) { continue }
  if (-not (Get-Service $name -ErrorAction SilentlyContinue)) { Write-Warning "Service not installed, skipped: $name"; continue }

  $sddl = ((sc.exe sdshow $name) -join '').Trim()
  # Remove any entry we added before, so re-runs stay clean
  $sddl = $sddl -replace "\(A;;[A-Z]+;;;$([regex]::Escape($sid))\)", ''

  $allowed = ($config.allowControl -ne $false) -and ($s.control -ne $false)
  if ($allowed) {
    # Insert our entry at the end of the DACL (before the SACL if there is one)
    $m = [regex]::Match($sddl, '^(?<pre>.*?D:[A-Z]*)(?<aces>(\([^)]*\))*)(?<rest>.*)$')
    if (-not $m.Success) { Write-Warning "Could not parse permissions for $name, skipped"; continue }
    $sddl = $m.Groups['pre'].Value + $m.Groups['aces'].Value + "(A;;$rights;;;$sid)" + $m.Groups['rest'].Value
  }

  $result = sc.exe sdset $name $sddl
  if ($LASTEXITCODE -ne 0) { Write-Warning "Failed to update permissions for ${name}: $result"; continue }
  if ($allowed) { "Can control: $name" } else { "Read-only:   $name" }
}

# --- Collector scheduled task (runs as SYSTEM every 2 minutes) ---
"`n--- Collector ---"
$taskName = 'svcdash-collector'
$taskPath = '\svcdash\'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\collect.ps1`" -OutDir `"$Dir\collected`""
$every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 3650)
$boot = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $every, $boot -Principal $principal -Settings $settings `
  -Description 'Service Dashboard: collects listening ports, firewall rules and logon events for the Security page.' -Force | Out-Null
Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
"Scheduled task: $taskPath$taskName (every 2 minutes, as SYSTEM)"

$out = "$Dir\collected\security.json"
for ($i = 0; $i -lt 30 -and -not (Test-Path $out); $i++) { Start-Sleep 2 }
if (Test-Path $out) {
  $c = Get-Content $out -Raw | ConvertFrom-Json
  "First collection: $(@($c.listeners).Count) listening ports, $(@($c.firewall.rules).Count) firewall rules, $(@($c.logons.failed).Count) failed logons in 24h"
  foreach ($e in @($c.errors)) { if ($e) { Write-Warning "Collector: $e" } }
  if ($c.logons -and $c.logons.failureAuditing -eq $false) {
    Write-Warning "Failed-logon auditing is off. Turn it on: auditpol /set /subcategory:`"Logon`" /success:enable /failure:enable"
  }
} else {
  Write-Warning "The collector hasn't produced data yet. Check Task Scheduler > svcdash > svcdash-collector."
}

# --- Start and verify ---
Start-Service $svc
Start-Sleep 3
""
Get-CimInstance Win32_Service -Filter "Name='$svc'" | Select-Object Name, State, StartMode, StartName | Format-Table -AutoSize

try {
  $port = if ($config.port) { $config.port } else { 3090 }
  $r = Invoke-WebRequest "http://127.0.0.1:$port/healthz" -UseBasicParsing
  "Health check: $($r.Content) -> open http://127.0.0.1:$port in a browser on this server"
} catch {
  Write-Warning "Health check failed. See $Dir\logs\err.log"
}
