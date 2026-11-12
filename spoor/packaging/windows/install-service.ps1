# Install or update the spoor Windows service. Run elevated.
# UNTESTED on Windows hardware in this release (see docs/LIMITATIONS.md).
#
# The service command line goes through New-Service and CIM, never
# `sc.exe ... binPath=`: Windows PowerShell 5.1 does not escape quotes
# embedded in a native argument, so sc.exe would receive `C:\Program` as the
# program (found by the Fleet script builder; deploy/fleet/README.md). Every
# native call checks its exit code. After an update the managed hook entries
# of agents that already have them are rewritten (entries written by an
# earlier release report "modified" until `spoor hooks install` runs again).
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

# Native tools report failure only through their exit code.
function Invoke-Native([string]$Tool, [string[]]$ArgList) {
  $ErrorActionPreference = 'Continue'
  $out = & $Tool @ArgList 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "$Tool $($ArgList -join ' ') failed with exit code $LASTEXITCODE. $out" }
}

$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($Uninstall) {
  if (Test-Path $Exe) {
    # Remove spoor's managed hook entries while the binary still exists.
    & $Exe hooks uninstall --scope managed | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'could not remove the managed hook entries' }
  }
  if ($svc) {
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    Invoke-Native sc.exe @('delete', $Name)
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
  Invoke-Native icacls.exe @($d, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
}
# Program directory is readable and executable by users (they run `spoor hook`).
Invoke-Native icacls.exe @($Dir, '/grant:r', '*S-1-5-32-545:(OI)(CI)RX')

if ($svc) { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
Copy-Item -Force -Path $Binary -Destination $Exe

if (-not (Test-Path $Config)) {
  & $Exe export config --out $Config | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Warning "could not write $Config; the service runs with built-in defaults" }
}

# The command line goes to the service manager as one string, exactly.
# New-Service runs the service as LocalSystem.
$bin = '"' + $Exe + '" run --config "' + $Config + '"'
$cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
if (-not $cim) {
  New-Service -Name $Name -BinaryPathName $bin -StartupType Automatic -DisplayName 'spoor AI agent detection sensor' -Description 'Detects risky AI coding agent activity and reports sensor health.' | Out-Null
} elseif ($cim.PathName -ne $bin) {
  $r = Invoke-CimMethod -InputObject $cim -MethodName Change -Arguments @{ PathName = $bin }
  if ($r.ReturnValue -ne 0) { throw "could not set the $Name service command line (Win32_Service.Change returned $($r.ReturnValue))" }
}
# Delayed automatic start; restart after 5 s on the first three failures and
# reset the count daily. No argument here contains quotes.
Invoke-Native sc.exe @('config', $Name, 'start=', 'delayed-auto')
Invoke-Native sc.exe @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/5000')
Start-Service -Name $Name

# Rewrite spoor's managed hook entries for agents that already have them.
$states = & $Exe hooks status --scope managed --json | Out-String
if ($LASTEXITCODE -eq 0 -and $states) {
  $hooked = @(($states | ConvertFrom-Json) | Where-Object { $_.status -in @('managed', 'modified', 'shadowed', 'insecure_permissions') } | ForEach-Object { $_.agent } | Select-Object -Unique)
  if ($hooked.Count -gt 0) {
    & $Exe hooks install --scope managed --agents ($hooked -join ',') | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not rewrite the managed hooks of $($hooked -join ',')" }
  }
}
Write-Output "spoor service installed: $Exe"
