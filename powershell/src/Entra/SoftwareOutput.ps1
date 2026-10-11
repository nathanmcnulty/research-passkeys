function Resolve-EntraSoftwareOutputPath {
    param([AllowNull()][string]$OutputPath, [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$DisplayName)
    $name = ($UserPrincipalName.Split('@')[0] + '_' + $DisplayName + '_credential.json') -replace '[^A-Za-z0-9_.-]', '_'
    if (-not $OutputPath) { return [IO.Path]::GetFullPath($name) }
    if ([IO.Directory]::Exists($OutputPath)) { $OutputPath = [IO.Path]::Combine($OutputPath, $name) }
    return [IO.Path]::GetFullPath($OutputPath)
}

function Open-EntraSoftwareCredentialOutput {
    param([Parameter(Mandatory)][string]$OutputPath)
    # Reserve before registration. Never silently overwrite a credential, including in pipeline mode.
    $parent = [IO.Path]::GetDirectoryName($OutputPath)
    if (-not [IO.Directory]::Exists($parent)) { throw 'Credential output directory does not exist.' }
    try {
        if ($IsWindows) {
            $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        } else {
            $options = [IO.FileStreamOptions]::new()
            $options.Mode = [IO.FileMode]::CreateNew; $options.Access = [IO.FileAccess]::Write; $options.Share = [IO.FileShare]::None
            $options.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            $stream = [IO.FileStream]::new($OutputPath, $options)
        }
        return $stream
    } catch { throw 'Credential output could not be reserved. Select a new writable private path; existing files are never overwritten.' }
}

function Write-EntraSoftwareCredentialOutput {
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Credential)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Credential | ConvertTo-Json -Depth 8))
    try { $Stream.Write($bytes, 0, $bytes.Length); $Stream.Flush() }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}
