function Export-PasskeyToGitHubSecret {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][object]$Credential,
        [Parameter(Mandatory)][string]$Repository,
        [switch]$ConsumersPaused
    )
    Assert-GitHubPasskeyRepository $Repository
    $values = Get-GitHubPasskeySecretValues $Credential
    if (-not $ConsumersPaused) { throw 'Pause all workflows/consumers and supply -ConsumersPaused. Four secret writes are not atomic.' }
    if (-not $PSCmdlet.ShouldProcess("github.com/$Repository", 'Replace four Actions secrets (metadata first, private key last; no rollback)')) { return }
    Test-GitHubPasskeyDestination $Repository
    $written = [Collections.Generic.List[string]]::new()
    foreach ($name in $values.Keys) {
        try {
            Invoke-GitHubPasskeyCli -Arguments @('secret','set',$name,'--repo',"github.com/$Repository",'--app','actions') -InputText $values[$name]
            $written.Add($name)
        } catch {
            $completed = if ($written.Count) { $written -join ', ' } else { '(none)' }
            throw "GitHub export incomplete. Confirmed writes: $completed. Failed or unknown: $name. Keep consumers paused. No rollback was attempted; GitHub cannot return previous secret values. Re-export the same complete credential if it remains available, or remove the orphaned Entra method and re-enroll."
        }
    }
    [pscustomobject]@{ Repository = $Repository; Success = $true; SecretNames = @($written); Atomic = $false }
}
