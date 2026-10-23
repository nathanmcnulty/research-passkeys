function Select-PreferredEstsCookie {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Cookies
    )

    foreach ($cookieName in @('ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT')) {
        $candidate = $Cookies | Where-Object {
            $_.Name -eq $cookieName -and $_.Value -and $_.Secure -and -not $_.Expired -and
            ($_.Expires -eq [datetime]::MinValue -or $_.Expires.ToUniversalTime() -gt [datetime]::UtcNow) -and
            $_.Domain.TrimStart('.') -in @('login.microsoftonline.com', 'login.microsoft.com', 'login.windows.net')
        } | Select-Object -First 1
        if ($candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-AllCookiesFromContainer {
    param(
        [Parameter(Mandatory)]
        [System.Net.CookieContainer]$CookieContainer
    )

    $allCookies = [System.Net.CookieCollection]::new()
    $getAllCookiesMethod = $CookieContainer.GetType().GetMethod('GetAllCookies', [System.Type[]]@())
    if ($getAllCookiesMethod) {
        foreach ($cookie in $getAllCookiesMethod.Invoke($CookieContainer, @())) {
            [void]$allCookies.Add($cookie)
        }

        return $allCookies
    }

    $bindingFlags = [System.Reflection.BindingFlags]'Instance, NonPublic'
    $domainTableField = $CookieContainer.GetType().GetField('m_domainTable', $bindingFlags)
    if (-not $domainTableField) {
        return $allCookies
    }

    $domainTable = $domainTableField.GetValue($CookieContainer)
    if (-not $domainTable) {
        return $allCookies
    }

    foreach ($pathList in $domainTable.Values) {
        if (-not $pathList) {
            continue
        }

        $pathListField = $pathList.GetType().GetField('m_list', $bindingFlags)
        if (-not $pathListField) {
            continue
        }

        $pathListTable = $pathListField.GetValue($pathList)
        if (-not $pathListTable) {
            continue
        }

        foreach ($cookieCollection in $pathListTable.Values) {
            foreach ($cookie in $cookieCollection) {
                [void]$allCookies.Add($cookie)
            }
        }
    }

    return $allCookies
}
