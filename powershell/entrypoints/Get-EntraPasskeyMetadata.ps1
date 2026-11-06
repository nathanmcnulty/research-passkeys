#Requires -Version 7.6

<#
.SYNOPSIS
Maps allowed and registered AAGUIDs to unverified FIDO MDS inventory descriptions.
.DESCRIPTION
Use -MdsPayload or -MdsJwt for offline fixture data. Otherwise downloads a bounded
public MDS JWT. -UseGraph opts into already-imported, already-connected Graph reads;
no connection, module import or consent is initiated. Explicit AAGUID arrays avoid Graph.
MDS signatures, certificate chains, freshness, status and attestation trust are not
validated. Results must not be used as attestation trust or security decisions.
.EXAMPLE
./Get-EntraPasskeyMetadata.ps1 -MdsPayload $fixture -AllowedAaguid $allowed -RegisteredAaguid $registered
#>
[CmdletBinding(DefaultParameterSetName = 'Download')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Payload')][ValidateNotNull()]$MdsPayload,
    [Parameter(Mandatory, ParameterSetName = 'Jwt')][ValidateNotNullOrEmpty()][string]$MdsJwt,
    [AllowEmptyCollection()][string[]]$AllowedAaguid = @(),
    [AllowEmptyCollection()][string[]]$RegisteredAaguid = @(),
    [switch]$UseGraph,
    [ValidateRange(1024, 33554432)][int]$MaximumMetadataBytes = 16777216,
    [ValidateRange(1, 60)][int]$DownloadTimeoutSeconds = 30
)

# Invoke public command
Get-EntraPasskeyMetadata @PSBoundParameters
