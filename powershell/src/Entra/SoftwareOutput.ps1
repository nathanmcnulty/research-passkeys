function Resolve-EntraSoftwareOutputPath {
    param([AllowNull()][string]$OutputPath, [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$DisplayName)
    $name = ($UserPrincipalName.Split('@')[0] + '_' + $DisplayName + '_credential.json') -replace '[^A-Za-z0-9_.-]', '_'
    if (-not $OutputPath) { $OutputPath = $name }
    # PowerShell's current location is independent of the process working directory.
    # Resolve through its provider before testing directories or opening private files.
    $provider = $null; $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputPath, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Credential output must use a filesystem path.' }
    if ([IO.Directory]::Exists($resolved)) { $resolved = [IO.Path]::Combine($resolved, $name) }
    return $resolved
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
    param([Parameter(Mandatory)][IO.FileStream]$Stream, [Parameter(Mandatory)]$Credential)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Credential | ConvertTo-Json -Depth 8))
    try {
        $Stream.Write($bytes, 0, $bytes.Length)
        # Enrollment may outlive this process. Do not submit a credential until its private
        # recovery record has reached stable storage rather than only the OS write cache.
        $Stream.Flush($true)
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}
