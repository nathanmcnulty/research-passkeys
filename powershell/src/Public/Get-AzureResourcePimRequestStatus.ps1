function Get-AzureResourcePimRequestStatus {
    <#
    .SYNOPSIS
    Reads back Azure resource-role PIM request status and active role assignment state.
    .DESCRIPTION
    Acquires one ARM token per operation (or reuses an in-memory -AccessToken) and queries
    Microsoft.Authorization/roleAssignmentScheduleRequests and roleAssignmentScheduleInstances
    (api-version 2020-10-01) at -Scope. Returns request ID, approval ID, scope, duration, status
    (such as PendingApprovalProvisioning or Provisioned), and matching active assignment state
    without credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [PSCustomObject]$CredentialFromPipeline,

        [Parameter(Mandatory = $true)]
        [string]$Scope,

        [Parameter(Mandatory = $false)]
        [string]$RequestId,

        [Parameter(Mandatory = $false)]
        [string]$RoleName,

        [Parameter(Mandatory = $false)]
        [string]$RoleDefinitionId,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAllActiveAssignments,

        [Parameter(Mandatory = $false)]
        [object]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$KeyFilePath,

        [Alias('UserName')]
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$UserHandle,

        [Alias('CredentialId')]
        [Parameter(Mandatory = $false)]
        $CredentialIdentifier,

        [Parameter(Mandatory = $false)]
        $PrivateKey,

        [Parameter(Mandatory = $false)]
        [string]$RelyingParty = 'login.microsoft.com',

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

        [Parameter(Mandatory = $false)]
        [string]$Claims,

        [Parameter(Mandatory = $false)]
        [string]$VerificationUri = 'https://login.microsoftonline.com/common/oauth2/deviceauth',

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

        [Parameter(Mandatory = $false)]
        [string]$Proxy,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultName,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultKeyName,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultAccessToken,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultClientId,

        [Parameter(Mandatory = $false)]
        [object]$KeyVaultClientSecret,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultTenantId,

        [Parameter(Mandatory = $false)]
        [switch]$Json
    )
    process {
        $targetScope = Resolve-AzurePimScope -Scope $Scope
        $normalizedRequestId = Normalize-OptionalString $RequestId
        if ($normalizedRequestId) {
            $parsedReq = [guid]::Empty
            if (-not [guid]::TryParse($normalizedRequestId, [ref]$parsedReq) -or $parsedReq -eq [guid]::Empty) {
                throw 'RequestId must be a nonempty GUID.'
            }
            $normalizedRequestId = $parsedReq.ToString()
        }
        $filterRoleGuid = if ($RoleDefinitionId) { Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $RoleDefinitionId } else { $null }
        $filterRoleName = Normalize-OptionalString $RoleName

        $tokenContext = $null
        try {
            $tokenContext = New-AzurePimTokenContext -BoundParameters $PSBoundParameters -CredentialFromPipeline $CredentialFromPipeline -QuietWarningsToStderr:$Json

            $instancesUri = New-AzurePimArmUri -Scope $targetScope -ProviderPath 'roleAssignmentScheduleInstances' -QueryString '$filter=asTarget()&api-version=2020-10-01'
            $rawInstances = Invoke-AzureResourcePimPagedGet -Context $tokenContext -Uri $instancesUri
            $parsedInstances = @($rawInstances | ForEach-Object { ConvertFrom-AzurePimAssignmentInstanceItem -Item $_ })

            $requestItems = if ($normalizedRequestId) {
                $singleUri = New-AzurePimArmUri -Scope $targetScope -ProviderPath "roleAssignmentScheduleRequests/$normalizedRequestId" -QueryString 'api-version=2020-10-01'
                @(Invoke-AzureResourcePimArmJson -Context $tokenContext -Uri $singleUri -Method 'GET')
            } else {
                $listUri = New-AzurePimArmUri -Scope $targetScope -ProviderPath 'roleAssignmentScheduleRequests' -QueryString '$filter=asTarget()&api-version=2020-10-01'
                Invoke-AzureResourcePimPagedGet -Context $tokenContext -Uri $listUri
            }

            $results = [System.Collections.Generic.List[pscustomobject]]::new()
            foreach ($reqItem in $requestItems) {
                if ($reqItem -isnot [System.Collections.IDictionary]) { continue }
                $converted = ConvertFrom-AzurePimRequestItem -Item $reqItem -ActiveInstances $parsedInstances
                if ($filterRoleGuid -and $converted.RoleDefinitionGuid -ine $filterRoleGuid) { continue }
                if ($filterRoleName -and $converted.RoleName -ine $filterRoleName) { continue }
                if ($IncludeAllActiveAssignments) {
                    $converted | Add-Member -NotePropertyName ActiveAssignments -NotePropertyValue $parsedInstances
                }
                $results.Add($converted)
            }

            if ($normalizedRequestId) {
                $single = $results | Select-Object -First 1
                if ($Json) { return ($single | ConvertTo-Json -Depth 10 -Compress) }
                return $single
            }

            if ($Json) { return (ConvertTo-Json -InputObject @($results) -Depth 10 -Compress) }
            return @($results)
        } finally {
            Clear-AzurePimTokenContext -Context $tokenContext
        }
    }
}
