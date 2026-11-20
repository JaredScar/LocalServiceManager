#Requires -RunAsAdministrator
# Downloads a GitHub release of this repo and installs or updates C:\apps\svcdash.
# Safe to re-run. config.json, state\, collected\, and logs\ are left in place.
# The dashboard service stops for a few seconds while install.ps1 recreates it.
#
# Elevated PowerShell:
#   $p = Join-Path $env:TEMP 'svcdash-setup.ps1'
#   Invoke-WebRequest https://github.com/JaredScar/LocalServiceManager/releases/latest/download/setup.ps1 -OutFile $p
#   Unblock-File $p
#   Set-ExecutionPolicy -Scope Process Bypass
#   & $p

param(
  [string]$Version = 'latest',
  [string]$Dir = 'C:\apps\svcdash',
  [string]$Node = 'C:\Program Files\nodejs\node.exe',
  [string]$Repo = 'JaredScar/LocalServiceManager'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not (Test-Path -LiteralPath $Node)) {
  throw "Node.js was not found at $Node. Install Node.js 18 or newer, or pass -Node."
}
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
  throw 'nssm is not on PATH. Install nssm, then open a new elevated PowerShell.'
}

function Get-Release($repo, $version) {
  $headers = @{
    'User-Agent' = 'svcdash-setup'
    Accept       = 'application/vnd.github+json'
  }
  if ($version -eq 'latest') {
    $uri = "https://api.github.com/repos/$repo/releases/latest"
  } else {
    $tag = $version
    if ($tag -notmatch '^v') { $tag = "v$tag" }
    $uri = "https://api.github.com/repos/$repo/releases/tags/$tag"
  }
  $release = Invoke-RestMethod -Headers $headers -Uri $uri
  if (-not $release.tag_name) {
    $why = $release.message
    if (-not $why) { $why = 'GitHub did not return a release.' }
    throw "Could not download $repo ($version). $why"
  }
  $asset = @($release.assets) | Where-Object { $_.name -eq 'LocalServiceManager.zip' } | Select-Object -First 1
  if (-not $asset) { throw "Release $($release.tag_name) has no LocalServiceManager.zip asset." }
  return $release, $asset
}

function Save-Url($url, $dest) {
  $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
  if ($curl) {
    & curl.exe -fL --retry 3 --retry-delay 2 -o $dest $url
    if ($LASTEXITCODE -ne 0) { throw "Download failed ($LASTEXITCODE): $url" }
    return
  }
  Invoke-WebRequest -Headers @{ 'User-Agent' = 'svcdash-setup' } -Uri $url -OutFile $dest -UseBasicParsing
}

$release, $asset = Get-Release $Repo $Version
$work = Join-Path $env:TEMP ("svcdash-setup-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $work | Out-Null

try {
  $zip = Join-Path $work 'LocalServiceManager.zip'
  $src = Join-Path $work 'src'
  Write-Output "Downloading $($release.tag_name)..."
  Save-Url $asset.browser_download_url $zip
  Expand-Archive -LiteralPath $zip -DestinationPath $src -Force
  if (-not (Test-Path -LiteralPath (Join-Path $src 'server.js'))) {
    throw 'The downloaded archive does not contain server.js.'
  }
  if (-not (Test-Path -LiteralPath (Join-Path $src 'lib\notify.js'))) {
    throw 'The downloaded archive does not contain lib\notify.js.'
  }

  New-Item -ItemType Directory -Path $Dir -Force | Out-Null
  Write-Output "Copying files to $Dir..."
  # 0-7 means robocopy copied or had nothing to copy. 8 and above are failures.
  # PowerShell 7 would otherwise treat those success codes as a failing command.
  $previousPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & robocopy $src $Dir /E /NFL /NDL /NJH /NP /XD state collected logs .git .github docs /XF config.json | Out-Null
  $copyExit = $LASTEXITCODE
  $ErrorActionPreference = $previousPreference
  if ($copyExit -ge 8) { throw "Copying into $Dir failed (robocopy exit $copyExit)." }

  Get-ChildItem -LiteralPath $Dir -Recurse -File | Unblock-File

  $config = Join-Path $Dir 'config.json'
  if (-not (Test-Path -LiteralPath $config)) {
    Copy-Item -LiteralPath (Join-Path $Dir 'config.example.json') -Destination $config
    Write-Output ""
    Write-Output "Created $config from the example."
    Write-Output "Edit it, using forward slashes in paths, then run this installer again."
    return
  }

  Write-Output "Installing $($release.tag_name). The dashboard will stop for a few seconds."
  & (Join-Path $Dir 'install.ps1') -Dir $Dir -Node $Node
}
finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
