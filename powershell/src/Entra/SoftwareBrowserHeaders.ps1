function Add-PasskeyBrowserHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    if (-not $Headers.ContainsKey('User-Agent')) {
        $Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
    }

    if (-not $Headers.ContainsKey('Accept')) {
        $Headers['Accept'] = '*/*'
    }

    if (-not $Headers.ContainsKey('Accept-Language')) {
        $Headers['Accept-Language'] = 'en-US'
    }

    if (-not $Headers.ContainsKey('sec-ch-ua')) {
        $Headers['sec-ch-ua'] = '"Chromium";v="149", "Microsoft Edge";v="149", "Not_A Brand";v="99"'
    }

    if (-not $Headers.ContainsKey('sec-ch-ua-mobile')) {
        $Headers['sec-ch-ua-mobile'] = '?0'
    }

    if (-not $Headers.ContainsKey('sec-ch-ua-platform')) {
        $Headers['sec-ch-ua-platform'] = '"Windows"'
    }

    if (-not $Headers.ContainsKey('Sec-Fetch-Dest')) {
        $Headers['Sec-Fetch-Dest'] = 'empty'
    }

    if (-not $Headers.ContainsKey('Sec-Fetch-Mode')) {
        $Headers['Sec-Fetch-Mode'] = 'cors'
    }

    if (-not $Headers.ContainsKey('Sec-Fetch-Site')) {
        $Headers['Sec-Fetch-Site'] = 'same-origin'
    }
}

