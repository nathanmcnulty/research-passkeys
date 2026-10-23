function Export-PasskeyToGitHubSecret {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param([Parameter(Mandatory)][object]$Credential, [Parameter(Mandatory)][string]$Repository)
    Assert-GitHubPasskeyRepository $Repository
    $values = Get-GitHubPasskeySecretValues $Credential
    if (-not $PSCmdlet.ShouldProcess("github.com/$Repository", 'Replace four Actions secrets (metadata first, private key last; no rollback)')) { return }
    Write-GitHubPasskeyExportWarning
    try { Test-GitHubPasskeyDestination $Repository }
    catch { $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage GitHubPreflight -CliFailure $_.TargetObject)) }
    Invoke-GitHubPasskeySecretExport -Values $values -Repository $Repository
}

function Write-GitHubPasskeyExportWarning {
    Write-Warning 'Four GitHub secret writes are not atomic. Pause or disable consumers yourself before continuing; this command does not pause them. Resume only after all four values are confirmed. Previous secret values cannot be recovered for rollback.'
}

function Invoke-GitHubPasskeySecretExport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Values, [Parameter(Mandatory)][string]$Repository,
        [ValidateSet('NotStarted','Verified')][string]$EnrollmentStatus = 'NotStarted')
    $written = [Collections.Generic.List[string]]::new()
    foreach ($name in $Values.Keys) {
        try {
            Invoke-GitHubPasskeyCli -Arguments @('secret','set',$name,'--repo',"github.com/$Repository",'--app','actions') -InputText $Values[$name]
            $written.Add($name)
        } catch {
            $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage GitHubExport -EnrollmentStatus $EnrollmentStatus `
                -ExportStatus Incomplete -ConfirmedWrites @($written) -FailedOrUnknownSecret $name -CliFailure $_.TargetObject))
        }
    }
    [pscustomobject]@{ Repository = $Repository; Success = $true; SecretNames = @($written); Atomic = $false
        EnrollmentStatus = $EnrollmentStatus; ExportStatus = 'Complete' }
}
