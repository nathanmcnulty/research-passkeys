#Requires -Version 7.6

<#
.SYNOPSIS
Load the GitHub secret exporter, or export an explicitly supplied in-memory credential.
.DESCRIPTION
Dot-sourcing without arguments loads functions only. Consumers must already be paused.
Four Actions secret writes (repository by default, environment with ProtectedLab) are non-atomic. Values are sent over stdin, never CLI arguments.
.PARAMETER ProtectedLab
Opt in to the fixed PASSKEY_LAB_* secret profile in an existing GitHub Environment. Requires Environment. Never falls back to repository secrets.
.PARAMETER Environment
Explicit existing environment name for ProtectedLab. Preflight requires nonempty valid reviewers and an exclusive selected-main branch policy. Read access does not guarantee write permission.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([object]$Credential, [string]$Repository, [switch]$ProtectedLab, [string]$Environment)

# Invoke public command
if ($PSBoundParameters.ContainsKey('Credential')) { Export-PasskeyToGitHubSecret @PSBoundParameters }
