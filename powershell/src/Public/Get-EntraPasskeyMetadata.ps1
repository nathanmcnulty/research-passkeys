function Get-EntraPasskeyMetadata {
    <#
    .SYNOPSIS
    Maps allowed and registered AAGUIDs to unverified FIDO MDS inventory descriptions.
    .DESCRIPTION
    Supply -MdsPayload or -MdsJwt for offline fixture data. Otherwise retrieves a bounded
    public MDS JWT from the fixed HTTPS MDS endpoint without following redirects.
    -UseGraph optionally reads already-imported, already-connected Microsoft Graph modules.
    It never connects Graph, imports modules, requests consent, or changes tenant settings.
    Supply -AllowedAaguid and -RegisteredAaguid to avoid Graph. Unknown AAGUIDs are retained.
    Downloaded MDS signatures, certificate chains, freshness, status and attestation trust
    are not validated. Results are inventory descriptions, not security/trust decisions.
    A Graph blocklist or unenforced restriction is reported as PolicyRestrictions, never
    mislabeled an explicit allowed list. This command replaces the historical implicit
    Graph/network script with explicit Graph opt-in and structured, unverified results.
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
    Invoke-EntraPasskeyMetadataUtility @PSBoundParameters
}
