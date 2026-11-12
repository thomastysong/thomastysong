# Remove the hawkbell sensor and its osquery extension registration.
# Fleet script for Windows (runs as SYSTEM); safe to run again.
# UNTESTED on Windows hardware in this release (deploy/fleet/VERIFIED.md).
# Keeps configuration and data unless $env:HAWKBELL_PURGE = '1'.
$ErrorActionPreference = 'Stop'
$Name = 'hawkbell'
$Dir  = Join-Path $env:ProgramFiles 'hawkbell'
$Ext  = Join-Path $Dir 'hawkbell.ext.exe'
$Data = Join-Path $env:ProgramData 'hawkbell'
$Load = Join-Path $env:ProgramFiles 'osquery\extensions.load'

# While the binary exists: no agent keeps calling it (fail-closed entries
# would block tool calls), as packaging/windows/install-service.ps1 does.
$Exe = Join-Path $Dir 'hawkbell.exe'
# system: Codex's machine tier, written by hooks install --scope system.
if (Test-Path $Exe) {
  & $Exe hooks uninstall --scope managed | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Warning 'managed hook entries not removed' }
  & $Exe hooks uninstall --scope system | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Warning 'system hook entries not removed' }
}

# sc.exe reports failure only through its exit code. No 2>&1: under
# 'Stop', Windows PowerShell 5.1 turns redirected stderr into an error.
if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
  Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
  $out = & sc.exe delete $Name | Out-String
  if ($LASTEXITCODE -ne 0) { throw "sc.exe delete $Name failed with exit code $LASTEXITCODE. $out" }
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
if ($env:HAWKBELL_PURGE -eq '1') { Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Path $Data }
Write-Output 'hawkbell removed'
