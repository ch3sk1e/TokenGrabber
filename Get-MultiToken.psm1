# ---------------------------------------------------------------------------
# TokenGrabber - Get-MultiToken
#
# The credential-based login flow in Invoke-CredentialLogin is adapted from
# Get-AccessToken.ps1 in AADInternals by Dr. Nestori Syynimaa (@DrAzureAD -
# https://github.com/Gerenios/AADInternals). The refresh-token redemption
# pattern was informed by TokenTacticsV2 (Fabian Bader, a fork of the
# original TokenTactics by Steve Borosh and Bobby Cooke -
# https://github.com/f-bader/TokenTacticsV2). See README.md for full credits.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Config / store plumbing
# ---------------------------------------------------------------------------

function Get-DefaultConfigPath {
    param([string]$FileName)
    Join-Path -Path $PSScriptRoot -ChildPath $FileName
}

function Import-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Resolve-ResourceAlias {
    param(
        [Parameter(Mandatory)][string]$Resource,
        [Parameter(Mandatory)][PSObject]$AliasMap
    )
    $key = $Resource.ToLowerInvariant()
    $prop = $AliasMap.PSObject.Properties[$key]
    if ($prop) { return $prop.Value }
    return $Resource
}

function Resolve-ClientSpec {
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][PSObject]$KnownClients
    )
    $key = $ClientId.ToLowerInvariant()
    $prop = $KnownClients.PSObject.Properties[$key]
    if ($prop) {
        return [PSCustomObject]@{
            ClientId    = $prop.Value.clientId
            DisplayName = $prop.Value.displayName
            RedirectUri = $prop.Value.redirectUri
        }
    }
    # Raw GUID - default redirect URI, best-effort
    return [PSCustomObject]@{
        ClientId    = $ClientId
        DisplayName = $ClientId
        RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    }
}

function Get-UserAgentString {
    param([string]$UserAgent = "desktop")
    switch ($UserAgent.ToLowerInvariant()) {
        "desktop" { return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Office/16.0 (Microsoft Outlook 16.0.13127; Pro)" }
        "mobile"  { return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" }
        default   { return $UserAgent }
    }
}

function Get-TokenStore {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $raw = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [PSCustomObject]@{ identities = [PSCustomObject]@{} }
        }
        return $raw | ConvertFrom-Json
    }
    return [PSCustomObject]@{ identities = [PSCustomObject]@{} }
}

function Save-TokenStore {
    param(
        [Parameter(Mandatory)][PSObject]$Store,
        [Parameter(Mandatory)][string]$Path
    )
    $Store | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-StoreKey {
    param([string]$Identity, [string]$ClientId)
    "$($Identity.ToLowerInvariant())|$($ClientId.ToLowerInvariant())"
}

function Find-StoreEntries {
    param(
        [Parameter(Mandatory)][PSObject]$Store,
        [Parameter(Mandatory)][string]$Identity,
        [string]$ClientId
    )
    $idLower = $Identity.ToLowerInvariant()
    $matches = @()
    foreach ($prop in $Store.identities.PSObject.Properties) {
        $entry = $prop.Value
        $entryId = if ($entry.upn) { $entry.upn } else { $entry.clientId }
        if ($entryId.ToLowerInvariant() -eq $idLower) {
            if ([string]::IsNullOrEmpty($ClientId) -or $entry.clientId -eq $ClientId) {
                $matches += [PSCustomObject]@{ Key = $prop.Name; Entry = $entry }
            }
        }
    }
    return $matches
}

function Resolve-ClientDisplayName {
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][PSObject]$KnownClients
    )
    foreach ($cprop in $KnownClients.PSObject.Properties) {
        if ($cprop.Value.clientId -eq $ClientId) { return $cprop.Value.displayName }
    }
    return $ClientId
}

function Get-StoreEntryList {
    <#
        Flattens the store into an indexed array - one row per (identity, clientId)
        entry, in the same order the JSON stores them. This order is stable between
        calls as long as the file isn't hand-edited or entries removed in between -
        -Index is a convenience, not a permanent ID.
    #>
    param(
        [Parameter(Mandatory)][PSObject]$Store,
        [Parameter(Mandatory)][PSObject]$KnownClients
    )
    $i = 0
    $list = @()
    foreach ($prop in $Store.identities.PSObject.Properties) {
        $e = $prop.Value
        $resourceSummary = @()
        if ($e.accessTokens) {
            foreach ($rp in $e.accessTokens.PSObject.Properties) {
                $exp = [DateTimeOffset]::FromUnixTimeSeconds($rp.Value.expiresOn).LocalDateTime
                $live = if ((Get-Date) -lt $exp) { "live" } else { "expired" }
                $shortName = ($rp.Name -replace '^https://', '' -replace '/$', '')
                $resourceSummary += "$shortName [$live]"
            }
        }
        $list += [PSCustomObject]@{
            Index       = $i
            Key         = $prop.Name
            Identity    = if ($e.upn) { $e.upn } else { "$($e.clientId) (app-only)" }
            Client      = Resolve-ClientDisplayName -ClientId $e.clientId -KnownClients $KnownClients
            AuthType    = $e.authType
            Resources   = ($resourceSummary -join ', ')
            LastUpdated = $e.lastUpdated
        }
        $i++
    }
    return $list
}

function Resolve-IdentityAndClient {
    <#
        Turns -Index into (Identity, ClientId) so the rest of the code only ever
        deals with -Identity/-ClientId - Index is purely a lookup convenience.
    #>
    param(
        [Parameter(Mandatory)][PSObject]$Store,
        [Parameter(Mandatory)][PSObject]$KnownClients,
        [Parameter(Mandatory)][int]$Index
    )
    $list = Get-StoreEntryList -Store $Store -KnownClients $KnownClients
    $row = $list | Where-Object { $_.Index -eq $Index }
    if (-not $row) {
        throw "No store entry at index $Index. Run -ListStore to see valid indices ($(if ($list.Count -gt 0) { "0..$($list.Count - 1)" } else { "store is empty" }))."
    }
    $entry = $Store.identities.($row.Key)
    $identity = if ($entry.upn) { $entry.upn } else { $entry.clientId }
    return [PSCustomObject]@{ Identity = $identity; ClientId = $entry.clientId }
}

# ---------------------------------------------------------------------------
# JWT decode (best-effort, no signature validation - local inspection only)
# ---------------------------------------------------------------------------

function ConvertFrom-JwtToken {
    param([Parameter(Mandatory)][string]$Token)
    try {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        $bytes = [Convert]::FromBase64String($payload)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        return $json | ConvertFrom-Json
    } catch {
        Write-Verbose "JWT decode failed: $_"
        return $null
    }
}

function Get-TokenScopes {
    <#
        .SYNOPSIS
        List the permission scopes/roles on any access token as an array - works on
        a token straight from $tokens[...], Get-StoredToken, or any raw token string.

        .EXAMPLE
        Get-TokenScopes -Token $tokens['https://graph.microsoft.com']

        .EXAMPLE
        Get-TokenScopes -Token (Get-StoredToken -Identity 'kathy@...' -Resource arm)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Token)
    $claims = ConvertFrom-JwtToken -Token $Token
    if ($null -eq $claims) { throw "Could not decode token." }
    if ($claims.scp)   { return $claims.scp -split ' ' }
    if ($claims.roles) { return $claims.roles }
    return @()
}

function Show-TokenSummary {
    param([Parameter(Mandatory)][string]$Resource, [Parameter(Mandatory)][string]$AccessToken)
    $claims = ConvertFrom-JwtToken -Token $AccessToken
    if ($null -eq $claims) {
        Write-Host "  [$Resource] (token minted - claims not decodable)" -ForegroundColor Yellow
        return
    }
    $scope = if ($claims.scp) { $claims.scp } elseif ($claims.roles) { ($claims.roles -join ', ') + ' (application permissions)' } else { '(none / app-only)' }
    Write-Host "  [$Resource]" -ForegroundColor Cyan
    Write-Host "    appid: $($claims.appid)   upn: $($claims.upn)$($claims.unique_name)   tid: $($claims.tid)"
    Write-Host "    scope: $scope"
}

# ---------------------------------------------------------------------------
# Auth flows
# ---------------------------------------------------------------------------

function Parse-LoginConfig {
    param([Parameter(Mandatory)][string]$Body)
    $startMarker = '$Config='
    $endMarker = '//]]>'
    $startIndex = $Body.IndexOf($startMarker)
    if ($startIndex -lt 0) { return $null }
    $endIndex = $Body.IndexOf($endMarker, $startIndex + $startMarker.Length)
    if ($endIndex -le $startIndex) { return $null }
    $rawText = $Body.Substring($startIndex + $startMarker.Length, $endIndex - $startIndex - $startMarker.Length)
    $configText = $rawText.TrimEnd(@(0x00, 0x0a, 0x0d, 0x3B))
    try { return $configText | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { return $null }
}

function Get-AadErrorMessage {
    param([string]$ErrorCode)
    try {
        $resp = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://login.microsoftonline.com/error?code=$ErrorCode"
        $startTag = '<td>Message</td><td>'; $endTag = '</td>'
        $startIndex = $resp.IndexOf($startTag)
        if ($startIndex -ge 0) {
            $endIndex = $resp.IndexOf($endTag, $startIndex + $startTag.Length)
            if ($endIndex -gt $startIndex) {
                return $resp.Substring($startIndex + $startTag.Length, $endIndex - $startIndex - $startTag.Length)
            }
        }
    } catch {}
    return "AADSTS error $ErrorCode (message lookup failed)"
}

function Invoke-CredentialLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Resource,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$UserAgentString
    )
    $headers = @{ "User-Agent" = $UserAgentString }
    $requestId = (New-Guid).ToString()
    $authorizeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/authorize?resource=$Resource&client_id=$ClientId&response_type=code&redirect_uri=$RedirectUri&client-request-id=$requestId&prompt=login&scope=openid profile&response_mode=query&sso_reload=True"

    $response = Invoke-WebRequest -UseBasicParsing -Uri $authorizeUrl -SessionVariable LoginSession -Method Get -MaximumRedirection 1 -ErrorAction SilentlyContinue -Headers $headers
    $config = Parse-LoginConfig -Body $response.Content

    $credCheckBody = @{
        username = $UserName; isOtherIdpSupported = $true; checkPhones = $true
        isRemoteNGCSupported = $true; isCookieBannerShown = $false; isFidoSupported = $true
        isAccessPassSupported = $true; originalRequest = $config.sCtx; flowToken = $config.sFT
    }
    $credType = Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/GetCredentialType" `
        -ContentType "application/json; charset=UTF-8" -Method Post -Body ($credCheckBody | ConvertTo-Json) `
        -WebSession $LoginSession -Headers $headers

    if ($credType.IfExistsResult -notin @(0, 5, 6)) {
        throw "User '$UserName' does not exist in tenant '$TenantId'."
    }

    $loginUrl = if ($config.urlPost.StartsWith("/")) { "https://login.microsoftonline.com$($config.urlPost)" } else { $config.urlPost }
    $loginBody = @{ login = $UserName; passwd = $Password; ctx = $config.sCtx; flowToken = $config.sFT; canary = $config.canary; client_id = $ClientId }
    $loginResponse = Invoke-WebRequest -UseBasicParsing -Uri $loginUrl -WebSession $LoginSession -Method Post -MaximumRedirection 0 -Headers $headers -Body $loginBody -ErrorAction SilentlyContinue

    $postConfig = Parse-LoginConfig -Body $loginResponse.Content

    if ($postConfig.pgid -eq "ConvergedConsent") {
        throw "App consent required for client_id '$ClientId' - consent to it in a browser first, then retry."
    }
    if ($postConfig.pgid -eq "KmsiInterrupt") {
        $kmsiBody = @{ LoginOptions = 1; ctx = $postConfig.sCtx; flowToken = $postConfig.sFT; canary = $postConfig.canary }
        $kmsiUrl = "https://login.microsoftonline.com$($postConfig.urlPost)"
        $loginResponse = Invoke-WebRequest -UseBasicParsing -Uri $kmsiUrl -WebSession $LoginSession -Method Post -MaximumRedirection 0 -Headers $headers -Body $kmsiBody -ErrorAction SilentlyContinue
        $postConfig = Parse-LoginConfig -Body $loginResponse.Content
    }

    if ($loginResponse.StatusCode -eq 200 -and $postConfig.sErrorCode) {
        throw (Get-AadErrorMessage -ErrorCode $postConfig.sErrorCode)
    }
    if ($loginResponse.StatusCode -ne 302) {
        throw "Login did not redirect (status $($loginResponse.StatusCode)) - likely an MFA challenge or unhandled interrupt page. Use -DeviceCode instead if MFA is actually enforced for this user."
    }

    $location = $loginResponse.Headers["Location"]
    if ($location -is [array]) { $location = $location[0] }
    $codeMatch = [regex]::Match($location, 'code=([^&]+)')
    if (-not $codeMatch.Success) {
        throw "No authorization code in redirect: $location"
    }
    $authCode = $codeMatch.Groups[1].Value

    $tokenBody = @{ client_id = $ClientId; grant_type = "authorization_code"; code = $authCode; redirect_uri = $RedirectUri }
    $tokenHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded"; "User-Agent" = $UserAgentString }
    $tokens = Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -Method Post -Body $tokenBody -Headers $tokenHeaders -ErrorAction Stop

    if (-not $tokens.access_token) { throw "Token exchange did not return an access_token." }
    return $tokens
}

function Invoke-DeviceCodeLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Resource,
        [string]$TenantId = "common",
        [int]$PollTimeoutSeconds = 300
    )
    $body = @{ client_id = $ClientId; scope = "$Resource/.default offline_access openid profile" }
    $authResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body $body -ErrorAction Stop

    Write-Host $authResponse.message -ForegroundColor Yellow

    $tokenBody = @{ client_id = $ClientId; grant_type = "urn:ietf:params:oauth:grant-type:device_code"; device_code = $authResponse.device_code }
    $deadline = (Get-Date).AddSeconds($PollTimeoutSeconds)
    $interval = [Math]::Max(2, [int]$authResponse.interval)

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $tokens = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $tokenBody -ErrorAction Stop
            return $tokens
        } catch {
            $err = $null
            try { $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch {}
            switch ($err) {
                "authorization_pending" { continue }
                "slow_down"             { $interval += 5; continue }
                "authorization_declined" { throw "Device code authorization was declined." }
                "expired_token"         { throw "Device code expired before authorization completed." }
                default                 { throw $_ }
            }
        }
    }
    throw "Device code polling timed out after $PollTimeoutSeconds seconds."
}

function Invoke-ClientCredentialLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Resource
    )
    $body = @{ client_id = $ClientId; client_secret = $ClientSecret; grant_type = "client_credentials"; scope = "$Resource/.default" }
    return Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ErrorAction Stop
}

function Invoke-RefreshTokenRedeem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RefreshToken,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Resource,
        [string]$TenantId = "common"
    )
    $body = @{ client_id = $ClientId; grant_type = "refresh_token"; refresh_token = $RefreshToken; scope = "$Resource/.default offline_access" }
    return Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
    Multi-audience Entra ID token grabber with a persistent local token store.

    .DESCRIPTION
    Seeds an identity (user credentials, device code, or app-only client credentials),
    mints access tokens for one or more resource audiences in a single call, and
    persists refresh tokens + cached access tokens to a local JSON store so later
    calls for the same identity never need fresh credentials again.

    Credential-based login uses a scripted emulation of the real interactive sign-in
    form (GetCredentialType -> form POST -> KMSI handling -> auth code -> token
    exchange) - the same mechanism as Get-AccessToken.ps1 - NOT the OAuth2 ROPC
    grant. It goes through full Conditional Access evaluation exactly like a real
    browser sign-in; it is not an MFA bypass on its own.

    Config files (same folder as this script, override with -ResourceAliasPath /
    -KnownClientsPath):
      resource-aliases.json  - short name -> resource URI  (arm, msgraph, aadgraph, vault, storage, outlook, ...)
      known-clients.json     - short name -> {clientId, displayName, redirectUri, notes}

    .PARAMETER ListStore
    Print everything currently held in the token store (identity, client, auth type,
    which resources have live tokens and their expiry) and exit.

    .PARAMETER ListClients
    Print every entry in known-clients.json (short name, client_id, display name,
    notes) - what you can pass to -ClientId.

    .PARAMETER ListResources
    Print every entry in resource-aliases.json (short name -> resource URI) -
    what you can pass to -Resources.

    .PARAMETER Identity
    Resume mode. Looks up an existing store entry by UserPrincipalName (or app-only
    ClientId) and mints/renews tokens for -Resources using its stored refresh token.
    No fresh credentials needed. If the identity has multiple entries under different
    ClientIds, pass -ClientId too to disambiguate.

    .PARAMETER UserName
    .PARAMETER Password
    Seed a new identity via the credential-based login-form emulation.

    .PARAMETER DeviceCode
    Seed a new identity via OAuth2 device code flow (supports interactive MFA at
    the verification URL - use this instead of -UserName/-Password when MFA is
    actually enforced).

    .PARAMETER ClientCredentials
    Seed an app-only identity via client-credentials grant. Requires -ClientId,
    -ClientSecret, and -TenantId (client credentials does not work against the
    /common/ endpoint - a real tenant ID or verified domain is required).

    .PARAMETER RefreshToken
    Seed an identity from a refresh_token obtained outside this script (e.g. an
    ESTSAUTH/ESTSAUTHPERSISTENT cookie-to-RT conversion via TokenTactics2, or any
    other tool). Redeems it for -Resources and stores the result exactly like any
    other identity, so it shows up in -ListStore alongside script-native entries.
    -ClientId is mandatory here - the RT must be redeemed against the client it
    was actually minted for, or a FOCI sibling of it; a mismatched client_id fails
    with invalid_grant.

    .PARAMETER Resources
    One or more resources to mint tokens for - resolved through resource-aliases.json
    first, falling back to the literal string as a URI if not a known alias.

    .PARAMETER ClientId
    Either a short name from known-clients.json (e.g. "teams", "intune", "office",
    "azurecli") or a raw client_id GUID. Never silently overridden by this script,
    unlike the original Get-AccessToken.ps1 (which force-swaps to Intune Company
    Portal whenever -resource is ARM) - a warning is printed instead if a pairing
    looks unusual.

    .PARAMETER UserAgent
    "desktop" or "mobile" (uses the exact verified UA strings from
    Get-AccessToken.ps1), or any literal User-Agent string.

    .PARAMETER Sweep
    Given a single resource, try it against every entry in known-clients.json and
    print a scope comparison - automates the "which client actually gives me the
    most here" discovery process instead of testing client_ids one at a time.

    .PARAMETER PassThru
    Also return the resource->rawToken hashtable to the pipeline. Off by default -
    printing a raw hashtable of JWTs to the host gets truncated/mangled by console
    width, same problem -ListStore had before it got a proper table. Default
    behavior is just the claims summary + a store confirmation; use
    Get-StoredToken (with -Clipboard if needed) as the one clean way to actually
    retrieve a copyable token, whether right after minting or later.

    .EXAMPLE
    Get-MultiToken -UserName 'jdoe@contoso.onmicrosoft.com' -Password 'P1aceholderPass!23' -ClientId teams -Resources msgraph,arm,aadgraph

    .EXAMPLE
    # Use when MFA is actually enforced - interactive prompt happens at the verification URL, not in this shell
    Get-MultiToken -DeviceCode -ClientId azurecli -Resources msgraph,arm -TenantId 'contoso.onmicrosoft.com'

    .EXAMPLE
    Get-MultiToken -Identity 'jdoe@contoso.onmicrosoft.com' -Resources vault

    .EXAMPLE
    Get-MultiToken -ListStore

    .EXAMPLE
    Get-MultiToken -ListClients

    .EXAMPLE
    Get-MultiToken -ListResources

    .EXAMPLE
    Get-MultiToken -Sweep -Resources msgraph -UserName 'user@tenant.com' -Password 'Pass123'

    .EXAMPLE
    # Import an RT obtained elsewhere (e.g. TokenTactics2) - client_id must match how it was minted
    Get-MultiToken -RefreshToken $stolenRt -ClientId azurecli -Resources msgraph,arm,vault

    .EXAMPLE
    # -PassThru for scripting - capture the hashtable directly instead of a second Get-StoredToken call
    $tokens = Get-MultiToken -UserName 'user@tenant.com' -Password 'Pass123' -Resources msgraph,arm -PassThru
    $tokens['https://graph.microsoft.com']

    .LINK
    https://github.com/Gerenios/AADInternals/
#>
function Get-MultiToken {
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param(
        [Parameter(ParameterSetName = 'List', Mandatory)][switch]$ListStore,
        [Parameter(ParameterSetName = 'ListClients', Mandatory)][switch]$ListClients,
        [Parameter(ParameterSetName = 'ListResources', Mandatory)][switch]$ListResources,

        [Parameter(ParameterSetName = 'Resume', Mandatory)][string]$Identity,
        [Parameter(ParameterSetName = 'ResumeByIndex', Mandatory)][int]$Index,

        [Parameter(ParameterSetName = 'Credential', Mandatory)][string]$UserName,
        [Parameter(ParameterSetName = 'Credential', Mandatory)][string]$Password,

        [Parameter(ParameterSetName = 'DeviceCode', Mandatory)][switch]$DeviceCode,

        [Parameter(ParameterSetName = 'ClientCredentials', Mandatory)][switch]$ClientCredentials,
        [Parameter(ParameterSetName = 'ClientCredentials', Mandatory)][string]$ClientSecret,

        [Parameter(ParameterSetName = 'RefreshToken', Mandatory)][string]$RefreshToken,

        [Parameter(ParameterSetName = 'Resume')]
        [Parameter(ParameterSetName = 'ResumeByIndex')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'DeviceCode')]
        [Parameter(ParameterSetName = 'ClientCredentials', Mandatory)]
        [Parameter(ParameterSetName = 'RefreshToken', Mandatory)]
        [string[]]$Resources,

        [Parameter(ParameterSetName = 'Resume')]
        [Parameter(ParameterSetName = 'ResumeByIndex')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'DeviceCode')]
        [Parameter(ParameterSetName = 'ClientCredentials', Mandatory)]
        [Parameter(ParameterSetName = 'RefreshToken', Mandatory)]
        [string]$ClientId = "azurecli",

        [string]$TenantId = "common",
        [string]$UserAgent = "desktop",
        [switch]$Sweep,
        [switch]$PassThru,

        [string]$StorePath = (Get-DefaultConfigPath "token-store.json"),
        [string]$ResourceAliasPath = (Get-DefaultConfigPath "resource-aliases.json"),
        [string]$KnownClientsPath = (Get-DefaultConfigPath "known-clients.json")
    )

    try {
    $aliasMap = Import-JsonFile -Path $ResourceAliasPath
    $knownClients = Import-JsonFile -Path $KnownClientsPath

    if ($ListClients) {
        $knownClients.PSObject.Properties | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.Name
                ClientId    = $_.Value.clientId
                DisplayName = $_.Value.displayName
                Notes       = $_.Value.notes
            }
        } | Format-Table -Property Name, ClientId, DisplayName, Notes -AutoSize -Wrap
        Write-Host "Use -ClientId <Name> (or a raw GUID) - config: $KnownClientsPath" -ForegroundColor DarkGray
        return
    }

    if ($ListResources) {
        $aliasMap.PSObject.Properties | ForEach-Object {
            [PSCustomObject]@{ Alias = $_.Name; Resource = $_.Value }
        } | Format-Table -Property Alias, Resource -AutoSize
        Write-Host "Use -Resources <Alias> (or any literal resource URI) - config: $ResourceAliasPath" -ForegroundColor DarkGray
        return
    }

    $store = Get-TokenStore -Path $StorePath

    if ($ListStore) {
        $list = Get-StoreEntryList -Store $store -KnownClients $knownClients
        if ($list.Count -eq 0) {
            Write-Host "Token store is empty ($StorePath)."
            return
        }
        $list | Format-Table -Property Index, Identity, Client, AuthType, Resources, LastUpdated -AutoSize -Wrap
        Write-Host "Use -Index <n> in place of -Identity to grab/refresh tokens, e.g.: Get-StoredToken -Index 0 -Resource arm" -ForegroundColor DarkGray
        return
    }

    $resolvedResources = $Resources | ForEach-Object { Resolve-ResourceAlias -Resource $_ -AliasMap $aliasMap }

    if ($PSCmdlet.ParameterSetName -eq 'ResumeByIndex') {
        $resolved = Resolve-IdentityAndClient -Store $store -KnownClients $knownClients -Index $Index
        $Identity = $resolved.Identity
        $ClientId = $resolved.ClientId   # exact match by construction - Index already disambiguates
    }

    if ($PSCmdlet.ParameterSetName -in @('Resume', 'ResumeByIndex')) {
        $lookupClientId = if ($PSCmdlet.ParameterSetName -eq 'ResumeByIndex') { $ClientId } elseif ($ClientId -ne 'azurecli') { (Resolve-ClientSpec -ClientId $ClientId -KnownClients $knownClients).ClientId } else { $null }
        $matches = Find-StoreEntries -Store $store -Identity $Identity -ClientId $lookupClientId
        if ($matches.Count -eq 0) {
            throw "No stored entry for '$Identity'. Seed it first with -UserName/-Password, -DeviceCode, or -ClientCredentials."
        }
        if ($matches.Count -gt 1) {
            Write-Host "Multiple stored entries match '$Identity' - pass -ClientId to disambiguate:" -ForegroundColor Yellow
            $matches | ForEach-Object { Write-Host "  clientId: $($_.Entry.clientId)" }
            return
        }
        $entry = $matches[0].Entry
        $key = $matches[0].Key
        $refreshToken = $entry.refreshToken
        $mintedClientId = $entry.clientId
        $result = @{}

        foreach ($res in $resolvedResources) {
            try {
                $tokens = Invoke-RefreshTokenRedeem -RefreshToken $refreshToken -ClientId $mintedClientId -Resource $res -TenantId $TenantId
                Show-TokenSummary -Resource $res -AccessToken $tokens.access_token
                if (-not $entry.accessTokens) { $entry | Add-Member -NotePropertyName accessTokens -NotePropertyValue ([PSCustomObject]@{}) }
                $expiresOn = [long][DateTimeOffset]::UtcNow.AddSeconds($tokens.expires_in).ToUnixTimeSeconds()
                $entry.accessTokens | Add-Member -NotePropertyName $res -NotePropertyValue ([PSCustomObject]@{ token = $tokens.access_token; expiresOn = $expiresOn }) -Force
                if ($tokens.refresh_token) { $entry.refreshToken = $tokens.refresh_token; $refreshToken = $tokens.refresh_token }
                $entry.lastUpdated = (Get-Date).ToString("o")
                $result[$res] = $tokens.access_token
            } catch {
                Write-Host "  [$res] FAILED: $_" -ForegroundColor Red
            }
        }
        $store.identities.$key = $entry
        Save-TokenStore -Store $store -Path $StorePath
        Write-Host "`nUpdated store entry: $key" -ForegroundColor DarkGray
        Write-Host "Retrieve a token cleanly with: Get-StoredToken -Identity '$Identity' -Resource <name> [-Clipboard]" -ForegroundColor DarkGray
        if ($PassThru) { return $result }
        return
    }

    if ($Sweep) {
        if ($resolvedResources.Count -ne 1) { throw "-Sweep takes exactly one resource." }
        $res = $resolvedResources[0]
        foreach ($cprop in $knownClients.PSObject.Properties) {
            $spec = Resolve-ClientSpec -ClientId $cprop.Name -KnownClients $knownClients
            Write-Host "`n== $($spec.DisplayName) ($($spec.ClientId)) ==" -ForegroundColor Magenta
            try {
                $tokens = Invoke-CredentialLogin -UserName $UserName -Password $Password -TenantId $TenantId -ClientId $spec.ClientId -Resource $res -RedirectUri $spec.RedirectUri -UserAgentString (Get-UserAgentString $UserAgent)
                Show-TokenSummary -Resource $res -AccessToken $tokens.access_token
            } catch {
                Write-Host "  FAILED: $_" -ForegroundColor Red
            }
        }
        return
    }

    $clientSpec = Resolve-ClientSpec -ClientId $ClientId -KnownClients $knownClients
    if ($resolvedResources -contains "https://management.azure.com" -and $clientSpec.DisplayName -notmatch "Intune|Azure CLI|Azure PowerShell") {
        Write-Host "Note: '$($clientSpec.DisplayName)' isn't a client typically pre-authorized for ARM - if this fails, try -ClientId azurecli or intune instead. (Not auto-switching - your explicit choice is kept.)" -ForegroundColor Yellow
    }

    $firstResource, $restResources = $resolvedResources[0], $resolvedResources[1..($resolvedResources.Count - 1)]
    $upn = $null
    $authType = $null

    if ($PSCmdlet.ParameterSetName -eq 'ClientCredentials' -and $TenantId -eq 'common') {
        throw "Client-credentials grants cannot use -TenantId 'common' - pass the real tenant domain or GUID (e.g. -TenantId 'contoso.onmicrosoft.com'). This is a hard Entra requirement, not a suggestion."
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Credential' {
                $tokens = Invoke-CredentialLogin -UserName $UserName -Password $Password -TenantId $TenantId -ClientId $clientSpec.ClientId -Resource $firstResource -RedirectUri $clientSpec.RedirectUri -UserAgentString (Get-UserAgentString $UserAgent)
                $upn = $UserName
                $authType = "Credential"
            }
            'DeviceCode' {
                $tokens = Invoke-DeviceCodeLogin -ClientId $clientSpec.ClientId -Resource $firstResource -TenantId $TenantId
                $claims = ConvertFrom-JwtToken -Token $tokens.access_token
                $upn = if ($claims.upn) { $claims.upn } else { $claims.unique_name }
                $authType = "DeviceCode"
            }
            'ClientCredentials' {
                $tokens = Invoke-ClientCredentialLogin -ClientId $clientSpec.ClientId -ClientSecret $ClientSecret -TenantId $TenantId -Resource $firstResource
                $authType = "ClientCredentials"
            }
            'RefreshToken' {
                $tokens = Invoke-RefreshTokenRedeem -RefreshToken $RefreshToken -ClientId $clientSpec.ClientId -Resource $firstResource -TenantId $TenantId
                $claims = ConvertFrom-JwtToken -Token $tokens.access_token
                $upn = if ($claims.upn) { $claims.upn } else { $claims.unique_name }
                $authType = "ImportedRefreshToken"
            }
        }
    } catch {
        Write-Host "Initial auth FAILED - nothing stored: $_" -ForegroundColor Red
        return
    }
    if (-not $tokens -or -not $tokens.access_token) {
        Write-Host "Initial auth returned no access_token - nothing stored." -ForegroundColor Red
        return
    }

    Show-TokenSummary -Resource $firstResource -AccessToken $tokens.access_token
    $result = @{ $firstResource = $tokens.access_token }

    $identityLabel = if ($upn) { $upn } else { $clientSpec.ClientId }
    $key = Get-StoreKey -Identity $identityLabel -ClientId $clientSpec.ClientId
    $expiresOn = [long][DateTimeOffset]::UtcNow.AddSeconds($tokens.expires_in).ToUnixTimeSeconds()
    $entry = [PSCustomObject]@{
        upn          = $upn
        clientId     = $clientSpec.ClientId
        authType     = $authType
        refreshToken = $tokens.refresh_token
        lastUpdated  = (Get-Date).ToString("o")
        accessTokens = [PSCustomObject]@{ $firstResource = [PSCustomObject]@{ token = $tokens.access_token; expiresOn = $expiresOn } }
    }

    $refreshToken = $tokens.refresh_token
    foreach ($res in $restResources) {
        if ($authType -eq "ClientCredentials") {
            try {
                $t = Invoke-ClientCredentialLogin -ClientId $clientSpec.ClientId -ClientSecret $ClientSecret -TenantId $TenantId -Resource $res
                Show-TokenSummary -Resource $res -AccessToken $t.access_token
                $exp = [long][DateTimeOffset]::UtcNow.AddSeconds($t.expires_in).ToUnixTimeSeconds()
                $entry.accessTokens | Add-Member -NotePropertyName $res -NotePropertyValue ([PSCustomObject]@{ token = $t.access_token; expiresOn = $exp })
                $result[$res] = $t.access_token
            } catch {
                Write-Host "  [$res] FAILED: $_" -ForegroundColor Red
            }
            continue
        }
        if (-not $refreshToken) {
            Write-Host "  [$res] SKIPPED: no refresh_token available from initial auth to redeem against additional resources." -ForegroundColor Yellow
            continue
        }
        try {
            $t = Invoke-RefreshTokenRedeem -RefreshToken $refreshToken -ClientId $clientSpec.ClientId -Resource $res -TenantId $TenantId
            Show-TokenSummary -Resource $res -AccessToken $t.access_token
            $exp = [long][DateTimeOffset]::UtcNow.AddSeconds($t.expires_in).ToUnixTimeSeconds()
            $entry.accessTokens | Add-Member -NotePropertyName $res -NotePropertyValue ([PSCustomObject]@{ token = $t.access_token; expiresOn = $exp })
            if ($t.refresh_token) { $refreshToken = $t.refresh_token; $entry.refreshToken = $t.refresh_token }
            $result[$res] = $t.access_token
        } catch {
            Write-Host "  [$res] FAILED: $_" -ForegroundColor Red
        }
    }

    $store.identities | Add-Member -NotePropertyName $key -NotePropertyValue $entry -Force
    Save-TokenStore -Store $store -Path $StorePath
    Write-Host "`nStored under key: $key" -ForegroundColor DarkGray
    Write-Host "Retrieve a token cleanly with: Get-StoredToken -Identity '$identityLabel' -Resource <name> [-Clipboard]" -ForegroundColor DarkGray
    if ($PassThru) { return $result }
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

function Get-StoredToken {
    <#
        .SYNOPSIS
        Pull one raw access token back out of the local store - for a new session,
        later today, or tomorrow - without re-minting anything.

        .EXAMPLE
        $armToken = Get-StoredToken -Identity 'jdoe@contoso.onmicrosoft.com' -Resource arm

        .EXAMPLE
        # -Index comes from the leftmost column of Get-MultiToken -ListStore's table -
        # quicker than typing the full UPN once you've already looked the entry up
        Get-StoredToken -Index 0 -Resource arm

        .EXAMPLE
        # -Clipboard sidesteps console line-wrapping entirely - no more trying to
        # select-copy a truncated/wrapped JWT out of the terminal
        Get-StoredToken -Identity 'jdoe@contoso.onmicrosoft.com' -Resource arm -Clipboard
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByIdentity')]
    param(
        [Parameter(ParameterSetName = 'ByIdentity', Mandatory)][string]$Identity,
        [Parameter(ParameterSetName = 'ByIndex', Mandatory)][int]$Index,
        [Parameter(Mandatory)][string]$Resource,
        [Parameter(ParameterSetName = 'ByIdentity')][string]$ClientId,
        [string]$StorePath = (Get-DefaultConfigPath "token-store.json"),
        [string]$ResourceAliasPath = (Get-DefaultConfigPath "resource-aliases.json"),
        [string]$KnownClientsPath = (Get-DefaultConfigPath "known-clients.json"),
        [switch]$AllowExpired,
        [switch]$Clipboard
    )
    try {
        $aliasMap = Import-JsonFile -Path $ResourceAliasPath
        $res = Resolve-ResourceAlias -Resource $Resource -AliasMap $aliasMap
        $store = Get-TokenStore -Path $StorePath

        if ($PSCmdlet.ParameterSetName -eq 'ByIndex') {
            $knownClients = Import-JsonFile -Path $KnownClientsPath
            $resolved = Resolve-IdentityAndClient -Store $store -KnownClients $knownClients -Index $Index
            $Identity = $resolved.Identity
            $ClientId = $resolved.ClientId
        }

        $matches = Find-StoreEntries -Store $store -Identity $Identity -ClientId $ClientId

        if ($matches.Count -eq 0) { throw "No stored entry for '$Identity'." }
        if ($matches.Count -gt 1) {
            Write-Host "Multiple stored entries match '$Identity' - pass -ClientId to disambiguate:" -ForegroundColor Yellow
            $matches | ForEach-Object { Write-Host "  clientId: $($_.Entry.clientId)" }
            return
        }

        $entry = $matches[0].Entry
        if (-not $entry.accessTokens -or -not $entry.accessTokens.PSObject.Properties[$res]) {
            throw "No cached token for resource '$res' on '$Identity'. Mint one first: Get-MultiToken -Identity '$Identity' -Resources '$Resource'"
        }
        $cached = $entry.accessTokens.$res
        $exp = [DateTimeOffset]::FromUnixTimeSeconds($cached.expiresOn).LocalDateTime
        if (-not $AllowExpired -and (Get-Date) -ge $exp) {
            throw "Cached token for '$res' expired at $exp. Refresh it: Get-MultiToken -Identity '$Identity' -Resources '$Resource'"
        }
        if ($Clipboard) {
            Set-Clipboard -Value $cached.token
            Write-Host "Token for '$res' copied to clipboard." -ForegroundColor DarkGray
        }
        return $cached.token
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

function Remove-StoredToken {
    <#
        .SYNOPSIS
        Delete one entry from the local token store, by -Identity or by -Index
        (from Get-MultiToken -ListStore's leftmost column).

        .EXAMPLE
        Remove-StoredToken -Index 2

        .EXAMPLE
        Remove-StoredToken -Identity 'cbd2f956-e186-4bb7-a56a-11f7a3ee437f'
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByIdentity')]
    param(
        [Parameter(ParameterSetName = 'ByIdentity', Mandatory)][string]$Identity,
        [Parameter(ParameterSetName = 'ByIndex', Mandatory)][int]$Index,
        [Parameter(ParameterSetName = 'ByIdentity')][string]$ClientId,
        [string]$StorePath = (Get-DefaultConfigPath "token-store.json"),
        [string]$KnownClientsPath = (Get-DefaultConfigPath "known-clients.json")
    )
    try {
        $store = Get-TokenStore -Path $StorePath
        $knownClients = Import-JsonFile -Path $KnownClientsPath

        if ($PSCmdlet.ParameterSetName -eq 'ByIndex') {
            $resolved = Resolve-IdentityAndClient -Store $store -KnownClients $knownClients -Index $Index
            $Identity = $resolved.Identity
            $ClientId = $resolved.ClientId
        }

        $matches = Find-StoreEntries -Store $store -Identity $Identity -ClientId $ClientId
        if ($matches.Count -eq 0) { throw "No stored entry for '$Identity'." }
        if ($matches.Count -gt 1) {
            Write-Host "Multiple stored entries match '$Identity' - pass -ClientId (or use -Index) to disambiguate:" -ForegroundColor Yellow
            $matches | ForEach-Object { Write-Host "  clientId: $($_.Entry.clientId)" }
            return
        }

        $key = $matches[0].Key
        $store.identities.PSObject.Properties.Remove($key)
        Save-TokenStore -Store $store -Path $StorePath
        Write-Host "Removed: $key" -ForegroundColor DarkGray
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

Export-ModuleMember -Function Get-MultiToken, Get-StoredToken, Get-TokenScopes, Remove-StoredToken
