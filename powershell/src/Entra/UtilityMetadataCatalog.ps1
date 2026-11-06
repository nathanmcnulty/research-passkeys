function Get-EntraPasskeyMetadataProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [Collections.IDictionary]) { return ,$InputObject[$Name] }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return ,$property.Value }
    return $null
}

function ConvertTo-EntraPasskeyAaguidList {
    param([AllowNull()][AllowEmptyCollection()][object[]]$Values)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Values) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParseExact([string]$value, 'D', [ref]$guid)) { throw 'AAGUID values must use the GUID D format.' }
        $normalized = $guid.ToString('D')
        if ($seen.Add($normalized)) { $normalized }
    }
}

function ConvertTo-EntraPasskeyMetadataCatalog {
    param([Parameter(Mandatory)]$Payload, [ValidateRange(1024, 33554432)][int]$MaximumBytes = 16777216)
    if ($Payload -is [string]) {
        if ([Text.Encoding]::UTF8.GetByteCount($Payload) -gt $MaximumBytes) { throw 'Metadata input exceeded its size limit.' }
        try { $Payload = $Payload | ConvertFrom-Json -Depth 100 -ErrorAction Stop }
        catch { throw 'MDS fixture JSON is malformed.' }
    } else {
        try { $length = [Text.Encoding]::UTF8.GetByteCount(($Payload | ConvertTo-Json -Depth 100 -Compress -ErrorAction Stop)) }
        catch { throw 'MDS fixture payload could not be serialized.' }
        if ($length -gt $MaximumBytes) { throw 'Metadata input exceeded its size limit.' }
    }
    $entries = Get-EntraPasskeyMetadataProperty $Payload 'entries'
    if ($null -eq $entries -or $entries -is [string] -or $entries -isnot [Collections.IEnumerable] -or
        $entries -is [Collections.IDictionary]) { throw 'MDS payload must contain an entries array.' }
    if (@($entries).Count -gt 50000) { throw 'MDS payload has too many entries.' }
    $catalog = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($entry in $entries) {
        $statement = Get-EntraPasskeyMetadataProperty $entry 'metadataStatement'
        $aaguid = Get-EntraPasskeyMetadataProperty $entry 'aaguid'
        if (-not $aaguid) { $aaguid = Get-EntraPasskeyMetadataProperty $statement 'aaguid' }
        # Some MDS authenticators are keyed only by AAID/certificate key IDs.
        if (-not $aaguid) { continue }
        $normalized = @(ConvertTo-EntraPasskeyAaguidList @($aaguid))[0]
        $statementAaguid = Get-EntraPasskeyMetadataProperty $statement 'aaguid'
        if ($statementAaguid -and @(ConvertTo-EntraPasskeyAaguidList @($statementAaguid))[0] -cne $normalized) {
            throw 'MDS entry and metadata statement AAGUID do not match.'
        }
        $description = [string](Get-EntraPasskeyMetadataProperty $statement 'description')
        if ($description.Length -gt 4096) { throw 'Metadata description exceeded its size limit.' }
        if ($catalog.ContainsKey($normalized)) { throw 'MDS payload contains duplicate AAGUID entries.' }
        $catalog.Add($normalized, [pscustomobject]@{
            Aaguid = $normalized; Description = $description; MetadataFound = $true; MetadataVerified = $false
        })
    }
    return @($catalog.Values | Sort-Object Aaguid)
}

function Select-EntraPasskeyMetadataEntries {
    param([AllowEmptyCollection()][object[]]$Catalog, [AllowEmptyCollection()][string[]]$Aaguids)
    $lookup = @{}
    foreach ($entry in $Catalog) { $lookup[$entry.Aaguid] = $entry }
    foreach ($aaguid in $Aaguids) {
        if ($lookup.ContainsKey($aaguid)) { $lookup[$aaguid] }
        else { [pscustomobject]@{ Aaguid = $aaguid; Description = $null; MetadataFound = $false; MetadataVerified = $false } }
    }
}

function Invoke-EntraPasskeyMetadataUtility {
    [CmdletBinding()]
    param(
        [AllowNull()]$MdsPayload,
        [string]$MdsJwt,
        [AllowEmptyCollection()][string[]]$AllowedAaguid = @(),
        [AllowEmptyCollection()][string[]]$RegisteredAaguid = @(),
        [switch]$UseGraph,
        [ValidateRange(1024, 33554432)][int]$MaximumMetadataBytes = 16777216,
        [ValidateRange(1, 60)][int]$DownloadTimeoutSeconds = 30
    )
    if ($PSBoundParameters.ContainsKey('MdsPayload') -and $PSBoundParameters.ContainsKey('MdsJwt')) {
        throw 'Specify either an MDS payload fixture or an MDS JWT, not both.'
    }
    $policy = $null
    $allowed = @(ConvertTo-EntraPasskeyAaguidList $AllowedAaguid)
    $registered = @(ConvertTo-EntraPasskeyAaguidList $RegisteredAaguid)
    if ($UseGraph) {
        $graph = Get-EntraPasskeyMetadataGraphData
        $policy = $graph.PolicyRestrictions
        if (-not $PSBoundParameters.ContainsKey('AllowedAaguid')) { $allowed = @($graph.AllowedAaguids) }
        if (-not $PSBoundParameters.ContainsKey('RegisteredAaguid')) { $registered = @($graph.RegisteredAaguids) }
    }
    if ($PSBoundParameters.ContainsKey('MdsPayload')) { $payload = $MdsPayload; $source = 'FixturePayload' }
    else {
        if ($PSBoundParameters.ContainsKey('MdsJwt')) { $jwt = $MdsJwt; $source = 'FixtureJwt' }
        else {
            $jwt = Invoke-EntraPasskeyMetadataDownload -MaximumBytes $MaximumMetadataBytes -TimeoutSeconds $DownloadTimeoutSeconds
            $source = 'https://mds3.fidoalliance.org/'
        }
        $payload = ConvertFrom-EntraPasskeyMdsJwt -Jwt $jwt -MaximumBytes $MaximumMetadataBytes
    }
    $catalog = @(ConvertTo-EntraPasskeyMetadataCatalog -Payload $payload -MaximumBytes $MaximumMetadataBytes)
    return [pscustomobject]@{
        Source = $source
        MetadataVerified = $false
        MetadataTrustWarning = 'MDS payload is unverified: signatures, certificate chains, freshness, status and attestation trust have not been validated. Use descriptions for inventory only.'
        UsedGraph = [bool]$UseGraph
        PolicyRestrictions = $policy
        AllowedAaguids = $allowed
        RegisteredAaguids = $registered
        AllowedEntries = @(Select-EntraPasskeyMetadataEntries -Catalog $catalog -Aaguids $allowed)
        RegisteredEntries = @(Select-EntraPasskeyMetadataEntries -Catalog $catalog -Aaguids $registered)
        CatalogEntries = $catalog
    }
}
