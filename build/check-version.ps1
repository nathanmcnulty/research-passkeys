#Requires -Version 7.6

<#
.SYNOPSIS
    Requires a deliberate version bump for source or build changes against a Git base.
.DESCRIPTION
    Compares the working tree to the merge base of HEAD and BaseRef, including
    untracked source/build files. Documentation and tests do not require a bump.
    Versions must have exactly three numeric SemVer components. A first introduction
    uses 0.1.0; rerunning an unchanged build never increments the version.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaseRef,
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::TrimEndingDirectorySeparator([System.IO.Path]::GetFullPath($RepositoryRoot))
$targets = Import-PowerShellDataFile (Join-Path $root 'build/targets.psd1')
$versionFile = [string]$targets.VersionFile
if ($versionFile -ne 'build/VERSION') { throw 'VersionFile must be build/VERSION.' }
$currentText = [System.IO.File]::ReadAllText((Join-Path $root $versionFile)).Trim()
function ConvertTo-SourceVersion {
    param([string]$Text, [string]$Location)
    if ($Text -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "Invalid version at ${Location}: use exactly three numeric SemVer components."
    }
    return [version]::Parse($Text)
}
$current = ConvertTo-SourceVersion $currentText $versionFile
$mergeBase = @(& git -C $root merge-base HEAD $BaseRef 2>$null)
if ($LASTEXITCODE -ne 0 -or $mergeBase.Count -ne 1) { throw "Cannot resolve a merge base for '$BaseRef'. Fetch the base history first." }
$base = [string]$mergeBase[0]
# Missing historical files are expected during first introduction. ls-tree returns
# zero for absence, so GitHub's pwsh LASTEXITCODE wrapper can report real success.
$oldVersionPaths = @(& git -C $root ls-tree --name-only $base -- $versionFile 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect the base source version file.' }
$oldExists = $oldVersionPaths -contains $versionFile
if (-not $oldExists) {
    if ($currentText -ne '0.1.0') { throw 'The initial source version must be 0.1.0.' }
    Write-Host 'Initial source version 0.1.0 accepted.'
    return
}
$oldLines = @(& git -C $root show "${base}:$versionFile" 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'Unable to read the base source version file.' }
$old = ConvertTo-SourceVersion (($oldLines -join "`n").Trim()) "$base`:$versionFile"
if ($current -lt $old) { throw "Source version cannot decrease: $old -> $current." }

function Get-ArtifactPaths {
    param([System.Collections.IDictionary]$Manifest)
    $modulePath = [string]$Manifest.ModulePath
    $moduleName = Split-Path -Leaf $modulePath
    return @("$modulePath/$moduleName.psm1", "$modulePath/$moduleName.psd1") + @($Manifest.Scripts | ForEach-Object { [string]$_.Path })
}
$artifactPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($path in Get-ArtifactPaths $targets) { $null = $artifactPaths.Add($path) }
$oldTargetPaths = @(& git -C $root ls-tree --name-only $base -- 'build/targets.psd1' 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect the base target inventory.' }
if ($oldTargetPaths -contains 'build/targets.psd1') {
    $oldTargetsText = @(& git -C $root show "${base}:build/targets.psd1" 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to read the base target inventory.' }
    $tokens = $null
    $parseErrors = $null
    $oldAst = [System.Management.Automation.Language.Parser]::ParseInput(($oldTargetsText -join "`n"), [ref]$tokens, [ref]$parseErrors)
    $statements = @($oldAst.EndBlock.Statements)
    if ($parseErrors.Count -gt 0 -or $statements.Count -ne 1 -or
        $statements[0] -isnot [System.Management.Automation.Language.PipelineAst] -or
        $statements[0].PipelineElements.Count -ne 1 -or
        $statements[0].PipelineElements[0] -isnot [System.Management.Automation.Language.CommandExpressionAst] -or
        $statements[0].PipelineElements[0].Expression -isnot [System.Management.Automation.Language.HashtableAst]) {
        throw 'Base target inventory is not a static PowerShell data file.'
    }
    $oldTargets = $statements[0].PipelineElements[0].Expression.SafeGetValue()
    foreach ($path in Get-ArtifactPaths $oldTargets) { $null = $artifactPaths.Add($path) }
}

# Explicit tree comparisons include staged and unstaged edits; untracked files are
# separate because git diff cannot see them. Deleted files also appear in --name-only.
$changed = @(& git -C $root diff --name-only --no-renames $base --)
if ($LASTEXITCODE -ne 0) { throw 'Unable to compare the source tree to the base.' }
$untracked = @(& git -C $root ls-files --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw 'Unable to list untracked source files.' }
$behaviorFiles = @(@($changed + $untracked) | Where-Object {
    ($_ -like 'powershell/src/*' -or $_ -like 'powershell/entrypoints/*' -or $_ -like 'build/*' -or
        $_ -eq '.github/workflows/passkey-ci.yml' -or
        $_ -eq 'github/action-passkey-login/.github/workflows/ci.yml' -or
        $_ -eq 'github/action-passkey-login/action.yml' -or
        ($_ -like 'github/action-passkey-login/scripts/*' -and $_ -like '*.ps1') -or
        $artifactPaths.Contains($_)) -and
    $_ -notlike 'build/tests/*' -and $_ -ne $versionFile -and
    $_ -notmatch '(^|/)(README[^/]*|[^/]+\.md)$'
} | Sort-Object -Unique)
if ($behaviorFiles.Count -gt 0 -and $current -le $old) {
    throw "Source/build changes require a deliberate version bump above $old. Changed: $($behaviorFiles -join ', ')"
}
Write-Host "Version check passed: $old -> $current ($($behaviorFiles.Count) source/build changes)."
