# Post-install script for the spoor msi in Fleet (Premium software
# deployment): register the installed binary as an osquery extension in
# osquery's default extensions.load (never orbit's) and restart osquery
# detached so the install reports first.
# UNTESTED on Windows hardware in this release (deploy/fleet/VERIFIED.md).
$ErrorActionPreference = 'Stop'
$Dir  = Join-Path $env:ProgramFiles 'spoor'
$Exe  = Join-Path $Dir 'spoor.exe'
$Ext  = Join-Path $Dir 'spoor.ext.exe'
$Load = Join-Path $env:ProgramFiles 'osquery\extensions.load'
if (-not (Test-Path $Exe)) { throw "spoor binary missing at $Exe" }
# When orbit's own autoload file is not empty (Fleet manages extensions on
# this host), orbit starts osquery with --extensions_autoload pointing at it
# and osquery ignores $Load. Fail, so Fleet reports why (and rolls back).
$OrbitLoad = Join-Path $env:ProgramFiles 'Orbit\extensions.load'
if ((Test-Path $OrbitLoad) -and (Get-Item -Force $OrbitLoad).Length -gt 0) {
  throw "orbit loads osquery extensions from $OrbitLoad (Fleet's extensions agent option), so osquery ignores $Load. Deliver spoor through that agent option, or deploy tier 2 (ATC) without this script."
}
$restart = $false
Remove-Item -Force -ErrorAction SilentlyContinue -Path "$Ext.old"
if (-not (Test-Path $Ext) -or (Get-FileHash $Exe).Hash -ne (Get-FileHash $Ext).Hash) {
  if (Test-Path $Ext) { Move-Item -Force -Path $Ext -Destination "$Ext.old" }
  Copy-Item -Force -Path $Exe -Destination $Ext
  $restart = $true
}
$lines = @()
if (Test-Path $Load) { $lines = @(Get-Content -Path $Load | Where-Object { $_ -ne '' }) }
if ($lines -notcontains $Ext) {
  New-Item -ItemType Directory -Force -Path (Split-Path $Load) | Out-Null
  Set-Content -Path $Load -Value (@($lines) + $Ext) -Encoding ASCII
  $restart = $true
}
if ($restart) {
  $osq = if (Get-Service -Name 'Fleet osquery' -ErrorAction SilentlyContinue) { 'Fleet osquery' } else { 'osqueryd' }
  $cmd = "Start-Sleep -Seconds 10; Restart-Service -Name '$osq' -Force"
  Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-Command', $cmd)
  Write-Output "osquery ($osq) restarts in 10 s to load $Ext"
}
