[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$sourceRelative = 'function-app/powershell/keyvault-passkey-http/src/'
$revision = [string](& git -C $repoRoot rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($revision)) {
    throw 'Cannot identify the source revision.'
}

$sourceChanges = @(& git -C $repoRoot status --porcelain --untracked-files=all -- $sourceRelative)
if ($LASTEXITCODE -ne 0 -or $sourceChanges.Count -ne 0) {
    throw 'Function source has local changes; commit and review them before packaging.'
}

$treeEntries = @(& git -C $repoRoot ls-tree -r $revision -- $sourceRelative)
if ($LASTEXITCODE -ne 0 -or $treeEntries.Count -eq 0) {
    throw 'No tracked Function source files were found.'
}
$entries = @($treeEntries | ForEach-Object {
    if ($_ -notmatch '^(100644|100755) blob [0-9a-f]{40,64}\t(.+)$') {
        throw "Function source contains an unsupported Git tree entry: $_"
    }
    $relative = $Matches[2].Substring($sourceRelative.Length)
    if ($relative -notmatch '(^|/)(local\.settings(\..*)?\.json|\.funcignore|\.gitignore)$') {
        $relative
    }
})
[array]::Sort($entries, [System.StringComparer]::Ordinal)
if ('host.json' -notin $entries -or 'requirements.psd1' -notin $entries) {
    throw 'The package is missing required PowerShell Functions root files.'
}

$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
$zipPath = Join-Path $outputRoot 'released-package.zip'
if (Test-Path -LiteralPath $zipPath) {
    throw "Package already exists: $zipPath"
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$sourceArchivePath = Join-Path ([System.IO.Path]::GetTempPath()) ("kvpp-source-$([guid]::NewGuid().ToString('N')).zip")
try {
    $sourceTree = '{0}:{1}' -f $revision, $sourceRelative.TrimEnd('/')
    & git -C $repoRoot archive --format=zip --output $sourceArchivePath $sourceTree
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not archive the committed Function source tree.'
    }
    $sourceArchive = [System.IO.Compression.ZipFile]::OpenRead($sourceArchivePath)
    try {
        $requirementsEntry = $sourceArchive.GetEntry('requirements.psd1')
        if ($null -eq $requirementsEntry) {
            throw 'The committed package is missing requirements.psd1.'
        }
        $reader = [System.IO.StreamReader]::new($requirementsEntry.Open())
        try {
            if ($reader.ReadToEnd() -notmatch '^\s*@\{\s*\}\s*$') {
                throw 'PowerShell managed dependencies are present; build and review a package that includes those dependencies.'
            }
        } finally {
            $reader.Dispose()
        }
        $stream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        try {
            $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
            try {
                foreach ($relative in $entries) {
                    $sourceEntry = $sourceArchive.GetEntry($relative)
                    if ($null -eq $sourceEntry) {
                        throw "Committed source entry is missing: $relative"
                    }
                    $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
                    $entry.LastWriteTime = [datetimeoffset]::new(1980, 1, 1, 0, 0, 0, [timespan]::Zero)
                    $sourceStream = $sourceEntry.Open()
                    $entryStream = $entry.Open()
                    try {
                        $sourceStream.CopyTo($entryStream)
                    } finally {
                        $entryStream.Dispose()
                        $sourceStream.Dispose()
                    }
                }
            } finally {
                $archive.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sourceArchive.Dispose()
    }
} finally {
    if (Test-Path -LiteralPath $sourceArchivePath) {
        Remove-Item -LiteralPath $sourceArchivePath -Force
    }
}

[pscustomobject]@{
    sourceRevision = $revision
    packagePath = $zipPath
    sha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    fileCount = $entries.Count
}
