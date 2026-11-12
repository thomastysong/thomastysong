# Install or update the hawkbell Windows service. Run elevated.
# UNTESTED on Windows hardware in this release (see docs/LIMITATIONS.md).
#
# The service command line goes through New-Service and CIM, never
# `sc.exe ... binPath=`: Windows PowerShell 5.1 does not escape quotes
# embedded in a native argument, so sc.exe would receive `C:\Program` as the
# program (found by the Fleet script builder; deploy/fleet/README.md). Every
# native call checks its exit code. After an update hawkbell's hook entries in
# the managed tier and Codex's system tier are rewritten where they already
# exist (`hawkbell hooks install --only-installed`: entries an earlier release
# wrote report "modified"
# until install runs again), keeping the options each file was installed
# with (--guard --fail-closed, --timeout); entries edited by hand are left
# as they are and listed, and agents never hooked stay unhooked.
# When hawkbell is registered as an osquery extension (deploy/fleet/scripts),
# the copy osquery runs is refreshed on update and unregistered on
# -Uninstall, as the Fleet scripts do.
#
#   powershell -ExecutionPolicy Bypass -File install-service.ps1 -Binary .\hawkbell.exe -Sha256 <hex>
#   powershell -ExecutionPolicy Bypass -File install-service.ps1 -Uninstall
param(
  [string]$Binary,
  [string]$Sha256,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$Name    = 'hawkbell'
$Dir     = Join-Path $env:ProgramFiles 'hawkbell'
$Exe     = Join-Path $Dir 'hawkbell.exe'
$Data    = Join-Path $env:ProgramData 'hawkbell'
$Config  = Join-Path $Data 'hawkbell.yaml'
# The osquery extension copy and osquery's autoload file, as
# deploy/fleet/scripts/install-hawkbell.ps1 and register-extension.ps1 use them.
$Ext     = Join-Path $Dir 'hawkbell.ext.exe'
$Load    = Join-Path $env:ProgramFiles 'osquery\extensions.load'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell.'
}

# Native tools report failure only through their exit code.
function Invoke-Native([string]$Tool, [string[]]$ArgList) {
  $ErrorActionPreference = 'Continue'
  $out = & $Tool @ArgList 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "$Tool $($ArgList -join ' ') failed with exit code $LASTEXITCODE. $out" }
}

# osquery holds a running extension until it restarts: restart it detached
# and delayed, so a script run by orbit (Fleet) reports first. $After runs
# once osquery has let go of the old file.
function Restart-OsqueryLater([string]$After) {
  $osq = if (Get-Service -Name 'Fleet osquery' -ErrorAction SilentlyContinue) { 'Fleet osquery' } else { 'osqueryd' }
  $cmd = "Start-Sleep -Seconds 10; Restart-Service -Name '$osq' -Force; $After"
  Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-Command', $cmd)
  Write-Output "osquery ($osq) restarts in 10 s"
}

function Get-LoadLines {
  if (Test-Path $Load) { return @(Get-Content -Path $Load | Where-Object { $_ -ne '' }) }
  return @()
}

$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($Uninstall) {
  if (Test-Path $Exe) {
    # Remove hawkbell's hook entries while the binary still exists: managed,
    # and Codex's machine tier (hooks install --scope system).
    & $Exe hooks uninstall --scope managed | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'could not remove the managed hook entries' }
    & $Exe hooks uninstall --scope system | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'could not remove the system hook entries' }
  }
  if ($svc) {
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    Invoke-Native sc.exe @('delete', $Name)
  }
  # Unregister the osquery extension; its copy goes once osquery let go of it.
  $lines = Get-LoadLines
  if ($lines -contains $Ext) {
    Set-Content -Path $Load -Value @($lines | Where-Object { $_ -ne $Ext }) -Encoding ASCII
    Restart-OsqueryLater "Start-Sleep -Seconds 5; Remove-Item -Force -ErrorAction SilentlyContinue -Path '$Ext', '$Ext.old'"
  } else {
    Remove-Item -Force -ErrorAction SilentlyContinue -Path $Ext, "$Ext.old"
  }
  Write-Output 'hawkbell service removed; data left in place under ProgramData\hawkbell.'
  exit 0
}

if (-not $Binary -or -not $Sha256) { throw '-Binary and -Sha256 are required.' }
$actual = (Get-FileHash -Algorithm SHA256 -Path $Binary).Hash.ToLowerInvariant()
if ($actual -ne $Sha256.ToLowerInvariant()) { throw "SHA-256 mismatch: got $actual" }

# Directories: SYSTEM and Administrators full control on everything below
# (no ACEs inherited from Program Files or ProgramData, whose default lets
# Users create files).
foreach ($d in @($Dir, $Data)) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  Invoke-Native icacls.exe @($d, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
}
# Program directory: Users read and execute (they run `hawkbell hook`).
Invoke-Native icacls.exe @($Dir, '/grant:r', '*S-1-5-32-545:(OI)(CI)RX')
# Data directory: it is also the configuration directory, and `hawkbell hook`
# runs as the developer and reads hawkbell.yaml there (an unreadable file means
# built-in defaults: no central guard mode, privacy profile or exclusions)
# and checks the kill switch file. Users get read and list on the directory
# itself only, not inherited: state.db and what the daemon writes later
# inherit SYSTEM and Administrators alone, and the daemon gives outbox,
# spool and bundle protected ACLs of their own (internal/daemon). hawkbell.yaml
# gets its own read grant below. hawkbell's own edit (hooks install --guard)
# copies the file's ACL onto its replacement; another tool that replaces
# hawkbell.yaml with a new file drops that grant: run this script again, or
# icacls hawkbell.yaml /grant *S-1-5-32-545:R.
Invoke-Native icacls.exe @($Data, '/grant:r', '*S-1-5-32-545:RX')

if ($svc) { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
Copy-Item -Force -Path $Binary -Destination $Exe

if (-not (Test-Path $Config)) {
  & $Exe export config --out $Config | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Warning "could not write $Config; the service runs with built-in defaults" }
}
# Hooks run as the developer and read the configuration (also repairs a file
# written by a release whose installer left Users without access).
if (Test-Path $Config) { Invoke-Native icacls.exe @($Config, '/grant:r', '*S-1-5-32-545:R') }

# osquery extension copy: refreshed when hawkbell is registered, or osquery
# keeps running the previous release. A running extension's file cannot be
# overwritten but can be renamed; the old copy goes once osquery restarts.
if ((Get-LoadLines) -contains $Ext) {
  $same = (Test-Path $Ext) -and ((Get-FileHash -Algorithm SHA256 $Exe).Hash -eq (Get-FileHash -Algorithm SHA256 $Ext).Hash)
  if (-not $same) {
    Remove-Item -Force -ErrorAction SilentlyContinue -Path "$Ext.old"
    if (Test-Path $Ext) { Move-Item -Force -Path $Ext -Destination "$Ext.old" }
    Copy-Item -Force -Path $Exe -Destination $Ext
    Restart-OsqueryLater "Start-Sleep -Seconds 5; Remove-Item -Force -ErrorAction SilentlyContinue -Path '$Ext.old'"
  }
}

# The command line goes to the service manager as one string, exactly.
# New-Service runs the service as LocalSystem.
$bin = '"' + $Exe + '" run --config "' + $Config + '"'
$cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
if (-not $cim) {
  New-Service -Name $Name -BinaryPathName $bin -StartupType Automatic -DisplayName 'hawkbell AI agent detection sensor' -Description 'Detects risky AI coding agent activity and reports sensor health.' | Out-Null
} elseif ($cim.PathName -ne $bin) {
  $r = Invoke-CimMethod -InputObject $cim -MethodName Change -Arguments @{ PathName = $bin }
  if ($r.ReturnValue -ne 0) { throw "could not set the $Name service command line (Win32_Service.Change returned $($r.ReturnValue))" }
}
# Delayed automatic start; restart after 5 s on the first three failures and
# reset the count daily. No argument here contains quotes.
Invoke-Native sc.exe @('config', $Name, 'start=', 'delayed-auto')
Invoke-Native sc.exe @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/5000')
Start-Service -Name $Name

# Hooks: --only-installed rewrites only the files that already hold hawkbell
# entries and reads each file's options back from them; it prints one line
# per file and exits 0 when there is nothing to do. Both machine tiers:
# managed, and Codex's system tier (hooks install --scope system).
& $Exe hooks install --only-installed --scope managed
if ($LASTEXITCODE -ne 0) { Write-Warning 'could not refresh the managed hooks; run: hawkbell.exe hooks install --only-installed --scope managed' }
& $Exe hooks install --only-installed --scope system
if ($LASTEXITCODE -ne 0) { Write-Warning 'could not refresh the system hooks; run: hawkbell.exe hooks install --only-installed --scope system' }
Write-Output "hawkbell service installed: $Exe"
