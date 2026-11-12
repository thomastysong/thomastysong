# Install or update the spoor Windows service. Run elevated.
# UNTESTED on Windows hardware in this release (see docs/LIMITATIONS.md).
#
#   powershell -ExecutionPolicy Bypass -File install-service.ps1 -Binary .\spoor.exe -Sha256 <hex>
#   powershell -ExecutionPolicy Bypass -File install-service.ps1 -Uninstall
param(
  [string]$Binary,
  [string]$Sha256,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$Name    = 'spoor'
$Dir     = Join-Path $env:ProgramFiles 'spoor'
$Exe     = Join-Path $Dir 'spoor.exe'
$Data    = Join-Path $env:ProgramData 'spoor'
$Config  = Join-Path $Data 'spoor.yaml'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell.'
}

$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($Uninstall) {
  if ($svc) {
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    & sc.exe delete $Name | Out-Null
  }
  Write-Output 'spoor service removed; data left in place under ProgramData\spoor.'
  exit 0
}

if (-not $Binary -or -not $Sha256) { throw '-Binary and -Sha256 are required.' }
$actual = (Get-FileHash -Algorithm SHA256 -Path $Binary).Hash.ToLowerInvariant()
if ($actual -ne $Sha256.ToLowerInvariant()) { throw "SHA-256 mismatch: got $actual" }

# Directories: SYSTEM and Administrators full control, nobody else (no inheritance).
foreach ($d in @($Dir, $Data)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  & icacls.exe $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}
# Program directory is readable and executable by users (they run `spoor hook`).
& icacls.exe $Dir /grant:r '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

if ($svc) { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
Copy-Item -Force -Path $Binary -Destination $Exe

if (-not (Test-Path $Config)) { & $Exe export config --out $Config | Out-Null }

$bin = '"' + $Exe + '" run --config "' + $Config + '"'
if (-not $svc) {
  & sc.exe create $Name binPath= $bin start= delayed-auto obj= LocalSystem DisplayName= 'spoor AI agent detection sensor' | Out-Null
} else {
  & sc.exe config $Name binPath= $bin start= delayed-auto | Out-Null
}
& sc.exe description $Name 'Detects risky AI coding agent activity and reports sensor health.' | Out-Null
# Restart after 5 s on the first three failures; reset the count daily.
& sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Start-Service -Name $Name
Write-Output "spoor service installed: $Exe"
