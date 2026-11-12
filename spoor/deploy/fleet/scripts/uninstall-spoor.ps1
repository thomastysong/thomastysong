# Remove the spoor sensor and its osquery extension registration.
# Fleet script for Windows (runs as SYSTEM); safe to run again.
# UNTESTED on Windows hardware in this release (deploy/fleet/VERIFIED.md).
# Keeps configuration and data unless $env:SPOOR_PURGE = '1'.
$ErrorActionPreference = 'Stop'
$Name = 'spoor'
$Dir  = Join-Path $env:ProgramFiles 'spoor'
$Ext  = Join-Path $Dir 'spoor.ext.exe'
$Data = Join-Path $env:ProgramData 'spoor'
$Load = Join-Path $env:ProgramFiles 'osquery\extensions.load'

if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
  Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
  & sc.exe delete $Name | Out-Null
}

$restart = $false
if (Test-Path $Load) {
  $lines = @(Get-Content -Path $Load | Where-Object { $_ -ne '' })
  if ($lines -contains $Ext) {
    Set-Content -Path $Load -Value @($lines | Where-Object { $_ -ne $Ext }) -Encoding ASCII
    $restart = $true
  }
}
if ($restart) {
  # osquery holds the extension until it restarts; do it detached so this
  # script reports first.
  $osq = if (Get-Service -Name 'Fleet osquery' -ErrorAction SilentlyContinue) { 'Fleet osquery' } else { 'osqueryd' }
  $cmd = "Start-Sleep -Seconds 10; Restart-Service -Name '$osq' -Force; Start-Sleep -Seconds 5; Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Path '$Dir'"
  Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-Command', $cmd)
  Write-Output "osquery ($osq) restarts in 10 s"
} else {
  Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Path $Dir
}
if ($env:SPOOR_PURGE -eq '1') { Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Path $Data }
Write-Output 'spoor removed'
