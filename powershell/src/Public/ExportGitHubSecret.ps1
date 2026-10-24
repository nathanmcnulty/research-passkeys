function Export-PasskeyToGitHubSecret {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param([Parameter(Mandatory)][object]$Credential, [Parameter(Mandatory)][string]$Repository, [switch]$ProtectedLab, [string]$Environment)
    Assert-GitHubPasskeyRepository $Repository
    Assert-GitHubPasskeyProfile -ProtectedLab:$ProtectedLab -Environment $Environment
    $values = Get-GitHubPasskeySecretValues $Credential -ProtectedLab:$ProtectedLab
    $destination = if ($ProtectedLab) { "github.com/$Repository environment $Environment (ProtectedLab)" } else { "github.com/$Repository repository (Legacy)" }
    if (-not $PSCmdlet.ShouldProcess($destination, 'Replace four Actions secrets (metadata first, private key last; no rollback)')) { return }
    Write-GitHubPasskeyExportWarning
    try { Test-GitHubPasskeyDestination $Repository -ProtectedLab:$ProtectedLab -Environment $Environment }
    catch { $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage GitHubPreflight -ProtectedLab:$ProtectedLab -CliFailure $_.TargetObject)) }
    Invoke-GitHubPasskeySecretExport -Values $values -Repository $Repository -ProtectedLab:$ProtectedLab -Environment $Environment
}

function Write-GitHubPasskeyExportWarning {
    Write-Warning 'Four GitHub secret writes are not atomic. Pause or disable consumers yourself before continuing; this command does not pause them. Resume only after all four values are confirmed. Previous secret values cannot be recovered for rollback.'
}

function Invoke-GitHubPasskeySecretExport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Values, [Parameter(Mandatory)][string]$Repository,
        [ValidateSet('NotStarted','Verified')][string]$EnrollmentStatus = 'NotStarted',
        [switch]$ProtectedLab, [string]$Environment)
    Assert-GitHubPasskeyProfile -ProtectedLab:$ProtectedLab -Environment $Environment
    $written = [Collections.Generic.List[string]]::new()
    foreach ($name in $Values.Keys) {
        try {
            $arguments = @('secret','set',$name,'--repo',"github.com/$Repository",'--app','actions')
            if ($ProtectedLab) { $arguments += @('--env', $Environment) }
            Invoke-GitHubPasskeyCli -Arguments $arguments -InputText $Values[$name]
            $written.Add($name)
        } catch {
            $PSCmdlet.ThrowTerminatingError((New-PasskeyOperationError -Stage GitHubExport -ProtectedLab:$ProtectedLab -EnrollmentStatus $EnrollmentStatus `
                -ExportStatus Incomplete -ConfirmedWrites @($written) -FailedOrUnknownSecret $name -CliFailure $_.TargetObject))
        }
    }
    [pscustomobject]@{ Repository = $Repository; Success = $true; SecretNames = @($written); Atomic = $false
        EnrollmentStatus = $EnrollmentStatus; ExportStatus = 'Complete'
        SecretProfile = $(if ($ProtectedLab) { 'ProtectedLab' } else { 'Legacy' }); Environment = $Environment }
}
