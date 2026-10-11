BeforeAll {
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $builder = Join-Path $repositoryRoot 'build/build.ps1'
    $versionGate = Join-Path $repositoryRoot 'build/check-version.ps1'
    $utf8 = [System.Text.UTF8Encoding]::new($false)

    function Write-FixtureFile {
        param([string]$Root, [string]$Path, [string]$Text)
        $fullPath = Join-Path $Root $Path
        $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($fullPath))
        [System.IO.File]::WriteAllText($fullPath, $Text.Replace("`r`n", "`n"), $utf8)
    }

    function New-BuildFixture {
        param([string]$Path)
        $null = New-Item -ItemType Directory -Path $Path -Force
        Write-FixtureFile $Path 'build/VERSION' "0.1.0`n"
        Write-FixtureFile $Path 'build/targets.psd1' @'
@{
    VersionFile = 'build/VERSION'
    ModulePath = 'powershell/modules/Passkey'
    GeneratedScriptDirectories = @('powershell/scripts')
    ModuleSources = @('powershell/src/private/Format-PasskeyGreeting.ps1', 'powershell/src/public/Get-PasskeyGreeting.ps1')
    Exports = @('Get-PasskeyGreeting')
    Scripts = @(
        @{ Path = 'powershell/scripts/Get-PasskeyGreeting.ps1'; EntryPoint = 'powershell/entrypoints/Get-PasskeyGreeting.ps1'; Sources = @('powershell/src/private/Format-PasskeyGreeting.ps1', 'powershell/src/public/Get-PasskeyGreeting.ps1') }
        @{ Path = 'powershell/scripts/GreetingAlias.ps1'; EntryPoint = 'powershell/entrypoints/Get-PasskeyGreeting.ps1'; Sources = @('powershell/src/private/Format-PasskeyGreeting.ps1', 'powershell/src/public/Get-PasskeyGreeting.ps1') }
    )
}
'@
        Write-FixtureFile $Path 'powershell/src/private/Format-PasskeyGreeting.ps1' @'
function Format-PasskeyGreeting {
    param([string]$Name)
    return "Hello, $Name"
}
'@
        Write-FixtureFile $Path 'powershell/src/public/Get-PasskeyGreeting.ps1' @'
function Get-PasskeyGreeting {
    [CmdletBinding()]
    param([string]$Name = 'fixture')
    Format-PasskeyGreeting -Name $Name
}
'@
        Write-FixtureFile $Path 'powershell/entrypoints/Get-PasskeyGreeting.ps1' @'
#Requires -Version 7.0

<#
.SYNOPSIS
    An offline fixture command.
#>
[CmdletBinding()]
param([string]$Name = 'fixture')

# Invoke public command
Get-PasskeyGreeting @PSBoundParameters
'@
        Copy-Item -LiteralPath $versionGate -Destination (Join-Path $Path 'build/check-version.ps1')
        Copy-Item -LiteralPath $builder -Destination (Join-Path $Path 'build/build.ps1')
        return $Path
    }

    function Initialize-FixtureGit {
        param([string]$Root, [switch]$WithoutVersion)
        & git -C $Root init --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Fixture Git init failed.' }
        & git -C $Root config user.email 'fixture@example.invalid'
        & git -C $Root config user.name 'Offline Fixture'
        if ($WithoutVersion) {
            Write-FixtureFile $Root 'README.md' "Initial repository`n"
            & git -C $Root add README.md
        } else {
            & git -C $Root add .
        }
        & git -C $Root commit --quiet -m 'Offline test base'
        if ($LASTEXITCODE -ne 0) { throw 'Fixture Git commit failed.' }
        return [string](& git -C $Root rev-parse HEAD)
    }

    function Invoke-GitHubExitWrapper {
        param([string]$Root, [string]$BaseRef, [switch]$StrictNativeErrors, [switch]$BuildCheck)
        $wrapper = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.ps1')
        $scriptText = @'
$ErrorActionPreference = 'Stop'
if ([Microsoft.PowerShell.Telemetry.ApplicationInsightsTelemetry]::CanSendTelemetry) {
    throw 'Telemetry must be disabled before PowerShell starts.'
}
__NATIVE_PREFERENCE__
Set-Location '__ROOT__'
__TOOL_COMMAND__
'@
        $toolCommand = if ($BuildCheck) { './build/build.ps1 -Check; if(Test-Path variable:\LASTEXITCODE){exit $LASTEXITCODE}' } else { './build/check-version.ps1 -BaseRef ''__BASE__''; if(Test-Path variable:\LASTEXITCODE){exit $LASTEXITCODE}' }
        $scriptText = $scriptText.Replace('__TOOL_COMMAND__', $toolCommand)
        $preference = if ($StrictNativeErrors) { '$PSNativeCommandUseErrorActionPreference = $true' } else { '$PSNativeCommandUseErrorActionPreference = $false' }
        $scriptText = $scriptText.Replace('__NATIVE_PREFERENCE__', $preference).Replace('__ROOT__', $Root.Replace("'", "''")).Replace('__BASE__', $BaseRef.Replace("'", "''"))
        [IO.File]::WriteAllText($wrapper, $scriptText, $utf8)
        $executable = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
        $oldTelemetry = $env:POWERSHELL_TELEMETRY_OPTOUT
        $oldDotnetTelemetry = $env:DOTNET_CLI_TELEMETRY_OPTOUT
        try {
            $env:POWERSHELL_TELEMETRY_OPTOUT = '1'
            $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
            # Nonzero child exit is returned for assertions instead of terminating Pester.
            $PSNativeCommandUseErrorActionPreference = $false
            $output = @(& $executable -NoLogo -NoProfile -File $wrapper 2>&1)
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output -join "`n" }
        } finally {
            $env:POWERSHELL_TELEMETRY_OPTOUT = $oldTelemetry
            $env:DOTNET_CLI_TELEMETRY_OPTOUT = $oldDotnetTelemetry
        }
    }

    function Get-ArtifactHashes {
        param([string]$Root)
        $files = @(
            'powershell/modules/Passkey/Passkey.psm1', 'powershell/modules/Passkey/Passkey.psd1',
            'powershell/scripts/Get-PasskeyGreeting.ps1', 'powershell/scripts/GreetingAlias.ps1'
        )
        return @($files | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $Root $_) -Algorithm SHA256).Hash })
    }
}

Describe 'Deterministic passkey build' {
    BeforeEach {
        $fixture = New-BuildFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
    }

    It 'rebuilds identical bytes and keeps alias targets identical' {
        & $builder -RepositoryRoot $fixture
        $first = Get-ArtifactHashes $fixture
        & $builder -RepositoryRoot $fixture
        (Get-ArtifactHashes $fixture) | Should -Be $first
        $first[2] | Should -Be $first[3]
        { & $builder -Check -RepositoryRoot $fixture } | Should -Not -Throw
    }

    It 'returns process zero for Check under the GitHub exit wrapper without historical targets' -ForEach @(
        @{ StrictNativeErrors = $false }, @{ StrictNativeErrors = $true }
    ) {
        $null = Initialize-FixtureGit $fixture -WithoutVersion
        & $builder -RepositoryRoot $fixture
        $result = Invoke-GitHubExitWrapper -Root $fixture -BuildCheck -StrictNativeErrors:$StrictNativeErrors
        $result.Output | Should -Match 'Generated artifact check passed'
        $result.ExitCode | Should -Be 0
    }

    It 'preserves no-commit Git repository builds under the GitHub exit wrapper' -ForEach @(
        @{ StrictNativeErrors = $false }, @{ StrictNativeErrors = $true }
    ) {
        & git -C $fixture init --quiet
        & $builder -RepositoryRoot $fixture
        $result = Invoke-GitHubExitWrapper -Root $fixture -BuildCheck -StrictNativeErrors:$StrictNativeErrors
        $result.Output | Should -Match 'Generated artifact check passed'
        $result.ExitCode | Should -Be 0
    }

    It 'does not mask a broken Git repository as an absent historical inventory' {
        $null = New-Item -ItemType Directory -Path (Join-Path $fixture '.git')
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*Unable to inspect*'
    }

    It 'uses UTF-8 without BOM, LF endings, source boundaries and version metadata' {
        & $builder -RepositoryRoot $fixture
        $path = Join-Path $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1'
        $bytes = [System.IO.File]::ReadAllBytes($path)
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        $bytes | Should -Not -Contain 13
        $text = [System.IO.File]::ReadAllText($path)
        $text | Should -Match 'Passkey source version: 0\.1\.0'
        $text | Should -Match '# Source: powershell/src/private/Format-PasskeyGreeting.ps1'
        $text | Should -Not -Match ([regex]::Escape($fixture))
        $text.IndexOf('param(') | Should -BeLessThan $text.IndexOf('function Format-PasskeyGreeting')
        $data = Import-PowerShellDataFile (Join-Path $fixture 'powershell/modules/Passkey/Passkey.psd1')
        $data.ModuleVersion | Should -Be '0.1.0'
        $data.FunctionsToExport | Should -Be @('Get-PasskeyGreeting')
    }

    It 'records an explicit module PowerShell minimum consistently' {
        Add-Content (Join-Path $fixture 'build/targets.psd1') '# fixture minimum version'
        $path = Join-Path $fixture 'build/targets.psd1'
        $text = [System.IO.File]::ReadAllText($path).Replace("VersionFile = 'build/VERSION'", "VersionFile = 'build/VERSION'`n    ModulePowerShellVersion = '7.6'")
        [System.IO.File]::WriteAllText($path, $text, $utf8)
        & $builder -RepositoryRoot $fixture
        $manifest = Import-PowerShellDataFile (Join-Path $fixture 'powershell/modules/Passkey/Passkey.psd1')
        $manifest.PowerShellVersion | Should -Be '7.6'
        [System.IO.File]::ReadAllText((Join-Path $fixture 'powershell/modules/Passkey/Passkey.psm1')) | Should -Match '^#Requires -Version 7\.6'
    }

    It 'imports only declared commands without executing a public command' {
        & $builder -RepositoryRoot $fixture
        $manifest = Join-Path $fixture 'powershell/modules/Passkey/Passkey.psd1'
        try {
            $module = Import-Module $manifest -Force -PassThru
            @($module.ExportedFunctions.Keys) | Should -Be @('Get-PasskeyGreeting')
            Get-PasskeyGreeting -Name 'module' | Should -Be 'Hello, module'
            & (Join-Path $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1') -Name 'standalone' | Should -Be 'Hello, standalone'
            $help = Get-Help (Join-Path $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1')
            $help.Synopsis.Trim() | Should -Be 'An offline fixture command.'
        } finally {
            Remove-Module Passkey -Force -ErrorAction SilentlyContinue
        }
    }

    It 'detects missing output without recreating it' {
        & $builder -RepositoryRoot $fixture
        $path = Join-Path $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1'
        Remove-Item $path
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*Missing:*'
        Test-Path $path | Should -BeFalse
    }

    It 'detects manual edits, BOMs and CRLF without correcting them' -ForEach @('Edit', 'BOM', 'CRLF') {
        & $builder -RepositoryRoot $fixture
        $path = Join-Path $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1'
        $text = [System.IO.File]::ReadAllText($path)
        switch ($_) {
            'Edit' { [System.IO.File]::WriteAllText($path, $text + '# edited', $utf8) }
            'BOM' { [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($true)) }
            'CRLF' { [System.IO.File]::WriteAllText($path, $text.Replace("`n", "`r`n"), $utf8) }
        }
        $before = (Get-FileHash $path).Hash
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*Stale or edited:*'
        (Get-FileHash $path).Hash | Should -Be $before
    }

    It 'detects stale output after a source edit' {
        & $builder -RepositoryRoot $fixture
        Add-Content -LiteralPath (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') -Value '# changed source'
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*artifact drift*'
    }

    It 'rejects extra untracked generated files and files in the dedicated module directory' -ForEach @('Script', 'Anonymous', 'Module') {
        & $builder -RepositoryRoot $fixture
        if ($_ -eq 'Script') {
            Copy-Item (Join-Path $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1') (Join-Path $fixture 'powershell/scripts/RemovedTarget.ps1')
        } elseif ($_ -eq 'Anonymous') {
            Write-FixtureFile $fixture 'powershell/scripts/Unexpected.ps1' '# no generated marker'
        } else {
            Write-FixtureFile $fixture 'powershell/modules/Passkey/unexpected.txt' 'stale file'
        }
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*Unexpected generated files*'
    }

    It 'detects removed targets from the previous tracked inventory even after header removal' {
        & $builder -RepositoryRoot $fixture
        $null = Initialize-FixtureGit $fixture
        $targets = Join-Path $fixture 'build/targets.psd1'
        $text = [System.IO.File]::ReadAllText($targets)
        $text = ($text -split "`n" | Where-Object { $_ -notmatch 'Path = .*GreetingAlias' }) -join "`n"
        [System.IO.File]::WriteAllText($targets, $text, $utf8)
        Write-FixtureFile $fixture 'powershell/scripts/GreetingAlias.ps1' '# header was removed'
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*Unexpected generated files*GreetingAlias*'
    }

    It 'rejects orphaned source units and entrypoints' -ForEach @('Source', 'EntryPoint') {
        if ($_ -eq 'Source') { Write-FixtureFile $fixture 'powershell/src/public/Orphan.ps1' 'function Get-Orphan {}' }
        else { Write-FixtureFile $fixture 'powershell/entrypoints/Orphan.ps1' '# orphan entrypoint' }
        { & $builder -Check -RepositoryRoot $fixture } | Should -Throw '*Unlisted source/entrypoint*'
    }

    It 'rejects parse errors before writing any output' {
        Write-FixtureFile $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1' 'function Get-PasskeyGreeting {'
        { & $builder -RepositoryRoot $fixture } | Should -Throw '*parse failure*'
        Test-Path (Join-Path $fixture 'powershell/modules/Passkey') | Should -BeFalse
    }

    It 'rejects source import-time execution, duplicate functions and undeclared exports' -ForEach @('Execution', 'Duplicate', 'Export') {
        switch ($_) {
            'Execution' { Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') 'Get-PasskeyGreeting' }
            'Duplicate' { Write-FixtureFile $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1' 'function Format-PasskeyGreeting { }' }
            'Export' {
                $path = Join-Path $fixture 'build/targets.psd1'
                [System.IO.File]::WriteAllText($path, ([System.IO.File]::ReadAllText($path).Replace("Exports = @('Get-PasskeyGreeting')", "Exports = @('Get-MissingCommand')")), $utf8)
            }
        }
        { & $builder -RepositoryRoot $fixture } | Should -Throw
    }

    It 'rejects missing or repeated invocation boundaries' -ForEach @('Missing', 'Repeated') {
        $path = Join-Path $fixture 'powershell/entrypoints/Get-PasskeyGreeting.ps1'
        $text = [System.IO.File]::ReadAllText($path)
        if ($_ -eq 'Missing') { $text = $text.Replace('# Invoke public command', '# no invocation marker') }
        else { $text += "`n# Invoke public command`n" }
        [System.IO.File]::WriteAllText($path, $text, $utf8)
        { & $builder -RepositoryRoot $fixture } | Should -Throw '*exactly one*'
    }
}

Describe 'Deliberate source version gate' {
    BeforeEach {
        $fixture = New-BuildFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
        $base = Initialize-FixtureGit $fixture
    }

    It 'accepts an unchanged rerun without a version increment' {
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Not -Throw
    }

    It 'rejects source, entrypoint, target and build edits without a bump' -ForEach @('Source', 'EntryPoint', 'Targets', 'Build', 'CI', 'DistributionCI', 'Action', 'ActionScript', 'Output', 'Module', 'Untracked', 'Deleted') {
        switch ($_) {
            'Source' { Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') '# change' }
            'EntryPoint' { Add-Content (Join-Path $fixture 'powershell/entrypoints/Get-PasskeyGreeting.ps1') '# change' }
            'Targets' { Add-Content (Join-Path $fixture 'build/targets.psd1') '# change' }
            'Build' { Write-FixtureFile $fixture 'build/build.ps1' '# changed build' }
            'CI' { Write-FixtureFile $fixture '.github/workflows/passkey-ci.yml' '# workflow change' }
            'DistributionCI' { Write-FixtureFile $fixture 'github/action-passkey-login/.github/workflows/ci.yml' '# distribution workflow change' }
            'Action' { Write-FixtureFile $fixture 'github/action-passkey-login/action.yml' '# public runtime change' }
            'ActionScript' { Write-FixtureFile $fixture 'github/action-passkey-login/scripts/Preflight.ps1' '# public script change' }
            'Output' { Write-FixtureFile $fixture 'powershell/scripts/Get-PasskeyGreeting.ps1' '# output change' }
            'Module' { Write-FixtureFile $fixture 'powershell/modules/Passkey/Passkey.psm1' '# module change' }
            'Untracked' { Write-FixtureFile $fixture 'powershell/src/public/New-Command.ps1' 'function New-Command {}' }
            'Deleted' { Remove-Item (Join-Path $fixture 'powershell/src/private/Format-PasskeyGreeting.ps1') }
        }
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Throw '*deliberate version bump*'
    }

    It 'keeps initial 0.1.0 valid across successive feature pushes against the default branch' {
        $initial = New-BuildFixture (Join-Path $TestDrive 'initial-feature-pushes')
        $defaultBase = Initialize-FixtureGit $initial -WithoutVersion
        & git -C $initial branch default-base $defaultBase
        & git -C $initial add .
        & git -C $initial commit --quiet -m 'Introduce package 0.1.0'
        $beforePush = [string](& git -C $initial rev-parse HEAD)
        Add-Content (Join-Path $initial 'powershell/src/public/Get-PasskeyGreeting.ps1') '# same reviewed package correction'
        & git -C $initial add .
        & git -C $initial commit --quiet -m 'Correct prerelease package tooling'
        { & $versionGate -RepositoryRoot $initial -BaseRef default-base } | Should -Not -Throw
        { & $versionGate -RepositoryRoot $initial -BaseRef $beforePush } | Should -Throw '*deliberate version bump*'
    }

    It 'keeps one future deliberate bump valid across successive feature corrections' {
        & git -C $fixture branch default-base $base
        Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') '# reviewed behavior change'
        Write-FixtureFile $fixture 'build/VERSION' "0.1.1`n"
        & git -C $fixture add .
        & git -C $fixture commit --quiet -m 'Bump package 0.1.1'
        Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') '# same package correction'
        { & $versionGate -RepositoryRoot $fixture -BaseRef default-base } | Should -Not -Throw
    }

    It 'still requires a deliberate bump against a default-branch push previous commit' {
        Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') '# main behavior change'
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Throw '*deliberate version bump*'
        Write-FixtureFile $fixture 'build/VERSION' "0.1.1`n"
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Not -Throw
    }

    It 'accepts an increased version for a behavior change' {
        Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') '# change'
        Write-FixtureFile $fixture 'build/VERSION' "0.1.1`n"
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Not -Throw
    }

    It 'compares against the merge base rather than unrelated base-branch edits' {
        & git -C $fixture checkout --quiet -b comparison-base
        Write-FixtureFile $fixture 'build/VERSION' "0.2.0`n"
        & git -C $fixture add .
        & git -C $fixture commit --quiet -m 'Base branch change'
        & git -C $fixture checkout --quiet -b feature $base
        { & $versionGate -RepositoryRoot $fixture -BaseRef comparison-base } | Should -Not -Throw
    }

    It 'allows documentation and build-test-only changes without a bump' {
        Write-FixtureFile $fixture 'build/README.md' 'Documentation only'
        Write-FixtureFile $fixture 'build/tests/New.Tests.ps1' 'Describe "offline" {}'
        Write-FixtureFile $fixture 'powershell/tests/New.Tests.ps1' 'Describe "offline" {}'
        Write-FixtureFile $fixture 'github/action-passkey-login/README.md' 'Documentation only'
        Write-FixtureFile $fixture 'github/action-passkey-login/examples/offline.yml' '# example only'
        Write-FixtureFile $fixture 'github/action-passkey-login/tests/New.Tests.ps1' 'Describe "offline" {}'
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Not -Throw
    }

    It 'rejects decreased and malformed versions' -ForEach @('0.0.9', 'v0.1.0', '0.1', '01.1.0', '0.1.1-preview', '0.1.0+build') {
        Write-FixtureFile $fixture 'build/VERSION' "$_`n"
        { & $versionGate -RepositoryRoot $fixture -BaseRef $base } | Should -Throw
        if ($_ -ne '0.0.9') { { & $builder -RepositoryRoot $fixture } | Should -Throw }
    }

    It 'returns process zero for first introduction under the exact GitHub exit wrapper' -ForEach @(
        @{ StrictNativeErrors = $false }, @{ StrictNativeErrors = $true }
    ) {
        $initial = New-BuildFixture (Join-Path $TestDrive ('initial-wrapper-' + [guid]::NewGuid().ToString('N')))
        $initialBase = Initialize-FixtureGit $initial -WithoutVersion
        $result = Invoke-GitHubExitWrapper -Root $initial -BaseRef $initialBase -StrictNativeErrors:$StrictNativeErrors
        $result.Output | Should -Match 'Initial source version 0\.1\.0 accepted'
        $result.ExitCode | Should -Be 0
    }

    It 'returns process zero for an unchanged existing version under the GitHub exit wrapper' {
        $result = Invoke-GitHubExitWrapper -Root $fixture -BaseRef $base -StrictNativeErrors
        $result.Output | Should -Match 'Version check passed'
        $result.ExitCode | Should -Be 0
    }

    It 'returns process zero when the historical target inventory is absent' {
        $targetText = [IO.File]::ReadAllText((Join-Path $fixture 'build/targets.psd1'))
        Remove-Item (Join-Path $fixture 'build/targets.psd1')
        & git -C $fixture add build/targets.psd1
        & git -C $fixture commit --quiet -m 'Base without target inventory'
        $withoutTargetsBase = [string](& git -C $fixture rev-parse HEAD)
        Write-FixtureFile $fixture 'build/targets.psd1' $targetText
        Write-FixtureFile $fixture 'build/VERSION' "0.1.1`n"
        $result = Invoke-GitHubExitWrapper -Root $fixture -BaseRef $withoutTargetsBase -StrictNativeErrors
        $result.Output | Should -Match 'Version check passed'
        $result.ExitCode | Should -Be 0
    }

    It 'still returns process failure for version policy errors under the GitHub exit wrapper' -ForEach @('SourceChange', 'InvalidVersion', 'MissingBase') {
        $wrapperBase = $base
        switch ($_) {
            'SourceChange' { Add-Content (Join-Path $fixture 'powershell/src/public/Get-PasskeyGreeting.ps1') '# source change' }
            'InvalidVersion' { Write-FixtureFile $fixture 'build/VERSION' "v0.1.0`n" }
            'MissingBase' { $wrapperBase = 'missing-base' }
        }
        (Invoke-GitHubExitWrapper -Root $fixture -BaseRef $wrapperBase).ExitCode | Should -Not -Be 0
    }

    It 'returns process failure for missing current VERSION against <History> history' -ForEach @(
        @{ History = 'initial' }, @{ History = 'versioned' }
    ) {
        if ($History -eq 'initial') {
            $fixture = New-BuildFixture (Join-Path $TestDrive 'missing-initial-version')
            $base = Initialize-FixtureGit $fixture -WithoutVersion
        }
        Remove-Item (Join-Path $fixture 'build/VERSION')
        (Invoke-GitHubExitWrapper -Root $fixture -BaseRef $base).ExitCode | Should -Not -Be 0
    }

    It 'accepts exactly 0.1.0 for first introduction and rejects other initial versions' {
        $initial = New-BuildFixture (Join-Path $TestDrive 'initial')
        $initialBase = Initialize-FixtureGit $initial -WithoutVersion
        { & $versionGate -RepositoryRoot $initial -BaseRef $initialBase } | Should -Not -Throw
        Write-FixtureFile $initial 'build/VERSION' "0.1.1`n"
        { & $versionGate -RepositoryRoot $initial -BaseRef $initialBase } | Should -Throw '*initial source version*'
    }

    It 'fails clearly when base history is unavailable' {
        { & $versionGate -RepositoryRoot $fixture -BaseRef 'missing-base' } | Should -Throw '*merge base*'
    }
}
