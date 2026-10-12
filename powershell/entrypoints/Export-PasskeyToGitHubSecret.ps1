#Requires -Version 7.6

<#
.SYNOPSIS
Load the GitHub secret exporter, or export an explicitly supplied in-memory credential.
.DESCRIPTION
Dot-sourcing without arguments loads functions only. Consumers must already be paused.
Four repository Actions secret writes are non-atomic. Values are sent over stdin, never CLI arguments.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([object]$Credential, [string]$Repository)

# Invoke public command
if ($PSBoundParameters.ContainsKey('Credential')) { Export-PasskeyToGitHubSecret @PSBoundParameters }
