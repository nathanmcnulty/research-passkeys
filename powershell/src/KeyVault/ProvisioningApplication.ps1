function Initialize-EntraKeyVaultProvisioningApplication {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServicePrincipalName, [bool]$CanGrantConsent)
    $name = $ServicePrincipalName.Replace("'", "''")
    $filter = [uri]::EscapeDataString("displayName eq '$name'")
    $apps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter" -Verbose:$false -Debug:$false -ErrorAction Stop
    if (@($apps.value).Count -gt 1) { throw 'Multiple applications have this display name; refusing an ambiguous target.' }
    if ($apps.value) { $app = @($apps.value)[0] }
    else {
        $body = @{ displayName = $ServicePrincipalName } | ConvertTo-Json
        $app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop
    }
    $filter = [uri]::EscapeDataString("appId eq '$($app.appId)'")
    $principals = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter" -Verbose:$false -Debug:$false -ErrorAction Stop
    if (@($principals.value).Count -gt 1) { throw 'Multiple service principals have this application ID.' }
    if ($principals.value) { $principal = @($principals.value)[0] }
    else {
        $body = @{ appId = $app.appId } | ConvertTo-Json
        $principal = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop
    }
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $filter = [uri]::EscapeDataString("appId eq '$graphAppId'")
    $graphPrincipals = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter" -Verbose:$false -Debug:$false -ErrorAction Stop
    $graph = @($graphPrincipals.value)[0]
    $permission = @($graph.appRoles | Where-Object { $_.value -eq 'UserAuthenticationMethod.ReadWrite.All' -and $_.allowedMemberTypes -contains 'Application' })[0]
    if (-not $permission.id) { throw 'Microsoft Graph passkey-management application role was not found.' }
    # Preserve permissions already present on a reused application.
    $required = [System.Collections.Generic.List[object]]::new()
    $graphAccess = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in @($app.requiredResourceAccess)) {
        if ($null -eq $resource) { continue }
        if ($resource.resourceAppId -eq $graphAppId) {
            foreach ($access in @($resource.resourceAccess)) { $graphAccess.Add($access) }
        } else { $required.Add($resource) }
    }
    if (-not @($graphAccess | Where-Object { $_.id -eq $permission.id -and $_.type -eq 'Role' }).Count) {
        $graphAccess.Add(@{ id = $permission.id; type = 'Role' })
    }
    $required.Add(@{ resourceAppId = $graphAppId; resourceAccess = @($graphAccess.ToArray()) })
    $body = @{ requiredResourceAccess = @($required.ToArray()) } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
    $consentGranted = $false
    if ($CanGrantConsent) {
        try {
            $grants = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($principal.id)/appRoleAssignments" -Verbose:$false -Debug:$false -ErrorAction Stop
            $existing = $grants.value | Where-Object { $_.appRoleId -eq $permission.id -and $_.resourceId -eq $graph.id }
            if (-not $existing) {
                $body = @{ principalId = $principal.id; resourceId = $graph.id; appRoleId = $permission.id } | ConvertTo-Json
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($principal.id)/appRoleAssignments" -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            }
            $consentGranted = $true
        } catch { Write-Warning 'Automatic admin consent failed; manual consent is required.' }
    } else { Write-Warning 'Admin consent must be granted manually.' }
    [pscustomobject]@{ ApplicationId = [string]$app.appId; ApplicationObjectId = [string]$app.id; ServicePrincipalId = [string]$principal.id; ConsentGranted = $consentGranted }
}
