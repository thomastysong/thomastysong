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
