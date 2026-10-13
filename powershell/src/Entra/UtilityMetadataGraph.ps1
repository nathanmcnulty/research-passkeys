# Optional Graph reads only. The caller must import and connect Graph separately.
function Get-EntraPasskeyMetadataGraphData {
    [CmdletBinding()]
    param()
    $commands = @{}
    foreach ($name in @('Get-MgContext', 'Get-MgPolicyAuthenticationMethodPolicy',
        'Get-MgReportAuthenticationMethodUserRegistrationDetail', 'Get-MgUserAuthenticationFido2Method')) {
        $found = @(Get-Command -Name $name -ListImported -ErrorAction SilentlyContinue)
        if ($found.Count -ne 1) { throw "Import the optional Microsoft Graph modules before using -UseGraph. Required command: $name" }
        $commands[$name] = $found[0]
    }
    try {
        $context = & $commands['Get-MgContext'] -ErrorAction Stop
        # App-only Graph contexts can have no Account value; Get-MgContext returning
        # null is the disconnected state. Required permissions are checked by Graph.
        if ($null -eq $context) { throw 'No connected Graph context.' }
        $policy = & $commands['Get-MgPolicyAuthenticationMethodPolicy'] -ErrorAction Stop -Verbose:$false -Debug:$false
        $configurations = @((Get-EntraPasskeyMetadataProperty $policy 'AuthenticationMethodConfigurations'))
        $fido = @($configurations | Where-Object { (Get-EntraPasskeyMetadataProperty $_ 'Id') -ieq 'Fido2' })
        if ($fido.Count -ne 1) { throw 'FIDO2 policy is missing or ambiguous.' }
        $restrictions = Get-EntraPasskeyMetadataProperty $fido[0] 'KeyRestrictions'
        if ($null -eq $restrictions) {
            $properties = Get-EntraPasskeyMetadataProperty $fido[0] 'AdditionalProperties'
            $restrictions = Get-EntraPasskeyMetadataProperty $properties 'keyRestrictions'
        }
        $policyAaguids = @(ConvertTo-EntraPasskeyAaguidList @((Get-EntraPasskeyMetadataProperty $restrictions 'aaGuids')))
        $isEnforced = (Get-EntraPasskeyMetadataProperty $restrictions 'isEnforced') -eq $true
        $mode = [string](Get-EntraPasskeyMetadataProperty $restrictions 'enforcementType')
        $allowed = @()
        # A configured block list or a disabled restriction is not an explicit allowed list.
        if ($isEnforced -and $mode -ieq 'allow') { $allowed = $policyAaguids }
        $users = @(& $commands['Get-MgReportAuthenticationMethodUserRegistrationDetail'] `
            -Filter "methodsRegistered/any(i:i eq 'passKeyDeviceBound')" -All -ErrorAction Stop -Verbose:$false -Debug:$false)
        $registered = [Collections.Generic.List[object]]::new()
        $seenUsers = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($user in $users) {
            $id = [string](Get-EntraPasskeyMetadataProperty $user 'Id')
            $guid = [guid]::Empty
            if (-not [guid]::TryParseExact($id, 'D', [ref]$guid) -or $guid -eq [guid]::Empty) { throw 'Graph registration report returned an invalid user ID.' }
            if (-not $seenUsers.Add($guid.ToString())) { continue }
            $methods = @(& $commands['Get-MgUserAuthenticationFido2Method'] -UserId $guid.ToString() -All `
                -ErrorAction Stop -Verbose:$false -Debug:$false)
            foreach ($method in $methods) {
                $aaguid = Get-EntraPasskeyMetadataProperty $method 'AaGuid'
                if ($aaguid) { $registered.Add($aaguid) }
            }
        }
        return [pscustomobject]@{
            AllowedAaguids = $allowed
            RegisteredAaguids = @(ConvertTo-EntraPasskeyAaguidList $registered.ToArray())
            PolicyRestrictions = [pscustomobject]@{ IsEnforced = $isEnforced; EnforcementType = $mode; Aaguids = $policyAaguids }
        }
    } catch { throw 'Connected Graph read failed or returned incomplete data. No connection or consent was initiated.' }
}
