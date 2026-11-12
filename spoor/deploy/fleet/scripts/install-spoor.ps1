# Install or update the spoor sensor and register it as an osquery extension.
# Fleet script for Windows (runs as SYSTEM); safe to run again.
# UNTESTED on Windows hardware in this release (deploy/fleet/VERIFIED.md).
# Set the URL and SHA-256 of each build below. A value may name a Fleet
# custom variable (FLEET_SECRET_* with a leading dollar sign): Fleet fills it
# in before the script runs, and fleetctl gitops then requires it to be set,
# even in a comment. $Tier must match the agent options: 'extension' (tier 3,
# agent options without spoor's ATC tables) or 'atc' (tier 2, ATC agent
# options; the extension is not registered). Fleet runs scripts without
# environment variables, so edit the default here; $env:SPOOR_TIER is for
# running the script by hand.
$ErrorActionPreference = 'Stop'
$Builds = @{
  'amd64' = @{ Url = 'https://downloads.example.com/spoor/0.1.0/spoor_windows_amd64.exe'; Sha256 = 'REPLACE_WITH_SHA256' }
  'arm64' = @{ Url = 'https://downloads.example.com/spoor/0.1.0/spoor_windows_arm64.exe'; Sha256 = 'REPLACE_WITH_SHA256' }
}
$Tier = if ($env:SPOOR_TIER) { $env:SPOOR_TIER } else { 'extension' }
if ($Tier -notin @('extension', 'atc')) { throw 'SPOOR_TIER must be extension or atc' }

$Name   = 'spoor'
$Dir    = Join-Path $env:ProgramFiles 'spoor'
$Exe    = Join-Path $Dir 'spoor.exe'
$Ext    = Join-Path $Dir 'spoor.ext.exe'
$Data   = Join-Path $env:ProgramData 'spoor'
$Config = Join-Path $Data 'spoor.yaml'
# osquery's default autoload file. Never orbit's (Program Files\Orbit):
# orbit rewrites that one itself.
$Load   = Join-Path $env:ProgramFiles 'osquery\extensions.load'
# But when orbit's file is not empty (Fleet manages extensions here, the
# extensions agent option), orbit starts osquery with --extensions_autoload
# pointing at it, osquery ignores $Load, and spoor would never load.
$OrbitLoad = Join-Path $env:ProgramFiles 'Orbit\extensions.load'
if ($Tier -eq 'extension' -and (Test-Path $OrbitLoad) -and (Get-Item -Force $OrbitLoad).Length -gt 0) {
  throw "orbit loads osquery extensions from $OrbitLoad (Fleet's extensions agent option), so osquery ignores $Load. Deliver spoor through that agent option, or use the atc tier with the ATC agent options."
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run as SYSTEM or an administrator' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$build = $Builds[$arch]
if ($build.Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "no valid SHA-256 configured for windows_$arch" }

# Native tools report failure only through their exit code. Fleet runs this
# with Windows PowerShell 5.1, which does not escape quotes embedded in a
# native argument, so no argument here carries quotes: the service command
# line goes through New-Service and CIM instead of sc.exe.
function Invoke-Native([string]$Tool, [string[]]$ArgList) {
  $ErrorActionPreference = 'Continue'
  $out = & $Tool @ArgList 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "$Tool $($ArgList -join ' ') failed with exit code $LASTEXITCODE. $out" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('spoor-' + [guid]::NewGuid().ToString('N') + '.exe')
try {
  if ($env:SPOOR_SRC) { Copy-Item -Path $env:SPOOR_SRC -Destination $tmp }
  else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $build.Url -OutFile $tmp
  }
  $got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLowerInvariant()
  if ($got -ne $build.Sha256.ToLowerInvariant()) { throw "SHA-256 mismatch for $($build.Url): got $got" }

  # SYSTEM and Administrators full control, nobody else; users may read and
  # run the program directory (they run `spoor hook`).
  foreach ($d in @($Dir, $Data)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Invoke-Native icacls.exe @($d, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
  }
  Invoke-Native icacls.exe @($Dir, '/grant:r', '*S-1-5-32-545:(OI)(CI)RX')
  # `spoor hook` runs as the developer and reads spoor.yaml in the data
  # directory (unreadable: built-in defaults, so no guard mode, privacy
  # profile or exclusions) and the kill switch there. Users may list that
  # directory itself, not inherited (state.db and the daemon's files keep
  # SYSTEM and Administrators only), and read spoor.yaml (granted below), as
  # packaging/windows/install-service.ps1 does.
  Invoke-Native icacls.exe @($Data, '/grant:r', '*S-1-5-32-545:RX')

  function Same($a, $b) {
    (Test-Path $b) -and ((Get-FileHash -Algorithm SHA256 $a).Hash -eq (Get-FileHash -Algorithm SHA256 $b).Hash)
  }
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  $binChanged = -not (Same $tmp $Exe)
  if ($binChanged) {
    if ($svc) { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
    Copy-Item -Force -Path $tmp -Destination $Exe
  }
  if (-not (Test-Path $Config)) {
    & $Exe export config --out $Config | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not write $Config" }
  }
  # Every run: also repairs a file an earlier release left unreadable.
  if (Test-Path $Config) { Invoke-Native icacls.exe @($Config, '/grant:r', '*S-1-5-32-545:R') }

  # The command line goes to the service manager as one string, exactly.
  $bin = '"' + $Exe + '" run --config "' + $Config + '"'
  $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
  if (-not $cim) {
    New-Service -Name $Name -BinaryPathName $bin -StartupType Automatic -DisplayName 'spoor AI agent detection sensor' -Description 'Detects risky AI coding agent activity and reports sensor health.' | Out-Null
  } elseif ($cim.PathName -ne $bin) {
    $r = Invoke-CimMethod -InputObject $cim -MethodName Change -Arguments @{ PathName = $bin }
    if ($r.ReturnValue -ne 0) { throw "could not set the $Name service command line (Win32_Service.Change returned $($r.ReturnValue))" }
  }
  Invoke-Native sc.exe @('config', $Name, 'start=', 'delayed-auto')
  Invoke-Native sc.exe @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/5000')
  if ((Get-Service -Name $Name).Status -ne 'Running') { Start-Service -Name $Name }

  # Hooks: entries an earlier release wrote read "modified" until
  # reinstalled. Only already-hooked agents, each with its own options;
  # system is Codex's machine tier (hooks install --scope system).
  & $Exe hooks install --only-installed --scope managed
  if ($LASTEXITCODE -ne 0) { Write-Warning 'managed hooks not refreshed' }
  & $Exe hooks install --only-installed --scope system
  if ($LASTEXITCODE -ne 0) { Write-Warning 'system hooks not refreshed' }

  Remove-Item -Force -ErrorAction SilentlyContinue -Path "$Ext.old"
  $restart = $false
  $lines = @()
  if (Test-Path $Load) { $lines = @(Get-Content -Path $Load | Where-Object { $_ -ne '' }) }
  if ($Tier -eq 'extension') {
    if (-not (Same $Exe $Ext)) {
      # A running extension's file cannot be overwritten, but it can be
      # renamed; the old copy is deleted by the next run.
      if (Test-Path $Ext) { Move-Item -Force -Path $Ext -Destination "$Ext.old" }
      Copy-Item -Force -Path $Exe -Destination $Ext
      $restart = $true
    }
    if ($lines -notcontains $Ext) {
      New-Item -ItemType Directory -Force -Path (Split-Path $Load) | Out-Null
      Set-Content -Path $Load -Value (@($lines) + $Ext) -Encoding ASCII
      $restart = $true
    }
  } elseif ($lines -contains $Ext) {
    Set-Content -Path $Load -Value @($lines | Where-Object { $_ -ne $Ext }) -Encoding ASCII
    $restart = $true
  }

  # Restart osquery detached and delayed: this script runs under orbit, and
  # restarting it synchronously would kill the script before it reports.
  if ($restart) {
    $osq = if (Get-Service -Name 'Fleet osquery' -ErrorAction SilentlyContinue) { 'Fleet osquery' } else { 'osqueryd' }
    $cmd = "Start-Sleep -Seconds 10; Restart-Service -Name '$osq' -Force"
    Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-Command', $cmd)
    Write-Output "osquery ($osq) restarts in 10 s to load $Ext"
  }
  Write-Output "spoor installed at $Exe (tier $Tier)"
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue -Path $tmp
}
