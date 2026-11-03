<#
  gource-team.ps1
  Plays a repo in Gource with display names and GitHub avatars for each contributor.
  Does not modify the repo: it renames authors in a temporary copy of Gource's log.

  Usage (from anywhere):
    powershell -ExecutionPolicy Bypass -File gource-team.ps1 -Repo "C:\path\to\project"

  Any extra arguments are passed straight to Gource, e.g.:
    powershell -ExecutionPolicy Bypass -File gource-team.ps1 -Repo . --start-date "2026-11-01" --stop-date "2026-11-03"
#>

param(
    [string]$Repo = ".",
    [double]$SecondsPerDay = 100,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GourceArgs
)

$ErrorActionPreference = "Stop"

# --- Contributors: git author name -> display name + GitHub username ---------
# Matching on the git name is case-insensitive.
$people = @{
    "soeun0609"     = @{ Display = "Soeun Kim";            GitHub = "soeun0609" }
    "JackaBoiGamez" = @{ Display = "Jackson Rodriguez";    GitHub = "JackaBoiGamez" }
    "Unknown"       = @{ Display = "Nileshkumar Hadiyel";  GitHub = "nevil-18" }
}

# --- Find gource.exe ----------------------------------------------------------
$gource = (Get-Command gource -ErrorAction SilentlyContinue).Source
if (-not $gource) {
    $candidates = @(
        "$env:ProgramFiles\Gource\gource.exe",
        "${env:ProgramFiles(x86)}\Gource\gource.exe"
    )
    $gource = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $gource) { throw "Could not find gource.exe. Add it to PATH or edit this script with its location." }

# --- Working folder next to this script ---------------------------------------
$work    = Join-Path $PSScriptRoot "gource-team"
$avatars = Join-Path $work "avatars"
New-Item -ItemType Directory -Force $avatars | Out-Null

# --- Download avatars, saved under the display name (what Gource will match) --
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
foreach ($p in $people.Values) {
    $file = Join-Path $avatars "$($p.Display).png"
    if (Test-Path $file) { continue }
    try {
        Write-Host "Downloading avatar for $($p.Display) ($($p.GitHub))..."
        Invoke-WebRequest "https://github.com/$($p.GitHub).png?size=128" -OutFile $file -UseBasicParsing
    } catch {
        Write-Warning "Could not download avatar for $($p.GitHub): $($_.Exception.Message)"
    }
}

# --- Export the repo history as a Gource log ----------------------------------
$rawLog     = Join-Path $work "raw.log"
$renamedLog = Join-Path $work "renamed.log"
& $gource --output-custom-log $rawLog (Resolve-Path $Repo).Path
if (-not (Test-Path $rawLog)) { throw "Gource did not produce a log. Is '$Repo' a git repository?" }

# --- Rename authors (format: timestamp|user|type|file|colour) -----------------
$lines = foreach ($line in [IO.File]::ReadAllLines($rawLog)) {
    $parts = $line.Split('|')
    if ($parts.Count -ge 2 -and $people.ContainsKey($parts[1])) {
        $parts[1] = $people[$parts[1]].Display
    }
    $parts -join '|'
}
[IO.File]::WriteAllLines($renamedLog, $lines, (New-Object Text.UTF8Encoding $false))

# --- Play it -------------------------------------------------------------------
& $gource $renamedLog `
    --user-image-dir $avatars `
    --seconds-per-day $SecondsPerDay `
    --auto-skip-seconds 5 `
    --file-idle-time 0 `
    --key `
    @GourceArgs