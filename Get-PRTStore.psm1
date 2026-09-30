# ---------------------------------------------------------------------------
# Standalone PRT + clear session key store - deliberately isolated from
# Get-MultiToken.psm1 (no shared code, no shared store file). A PRT + session
# key is a different class of material (mints anything as that identity via
# roadtx, not a single resource-scoped bearer token) so it gets its own file,
# its own schema, and its own functions.
# ---------------------------------------------------------------------------

function Get-DefaultPRTStorePath {
    Join-Path -Path $PSScriptRoot -ChildPath "prt-store.json"
}

function Get-PRTStoreData {
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

function Save-PRTStoreData {
    param(
        [Parameter(Mandatory)][PSObject]$Store,
        [Parameter(Mandatory)][string]$Path
    )
    $Store | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-PRTStoreKey {
    param([string]$Identity, [string]$DeviceId)
    if ([string]::IsNullOrEmpty($DeviceId)) {
        return $Identity.ToLowerInvariant()
    }
    "$($Identity.ToLowerInvariant())|$($DeviceId.ToLowerInvariant())"
}

function Get-PRTStoreEntryList {
    param([Parameter(Mandatory)][PSObject]$Store)
    $i = 0
    $list = @()
    foreach ($prop in $Store.identities.PSObject.Properties) {
        $e = $prop.Value
        $list += [PSCustomObject]@{
            Index       = $i
            Key         = $prop.Name
            Identity    = $e.identity
            DeviceId    = if ($e.deviceId) { $e.deviceId } else { "-" }
            Notes       = $e.notes
            LastUpdated = $e.lastUpdated
        }
        $i++
    }
    return $list
}

function Resolve-PRTIdentity {
    <#
        Turns -Index into a store Key, same convenience pattern as
        Get-MultiToken's -Index handling, kept local/duplicated here on
        purpose to avoid any cross-module dependency.
    #>
    param(
        [Parameter(Mandatory)][PSObject]$Store,
        [Parameter(Mandatory)][int]$Index
    )
    $list = Get-PRTStoreEntryList -Store $Store
    $row = $list | Where-Object { $_.Index -eq $Index }
    if (-not $row) {
        throw "No PRT store entry at index $Index. Run -ListStore to see valid indices ($(if ($list.Count -gt 0) { "0..$($list.Count - 1)" } else { "store is empty" }))."
    }
    return $row.Key
}

function Add-StoredPRT {
    <#
        .SYNOPSIS
        Save a clear (decrypted) PRT + session key for an identity, so it can
        be looked up later without re-running sekurlsa::evasive-cloudap /
        dpapi::cloudapkd every time.

        .PARAMETER Identity
        UPN or other label for whose PRT this is (e.g. 'asmith@contoso.onmicrosoft.com').

        .PARAMETER PRT
        Clear (decrypted) PRT value.

        .PARAMETER SessionKey
        Clear (decrypted) session key value.

        .PARAMETER DeviceId
        Optional - the device this PRT was extracted from, if you might hold
        PRTs for the same identity from more than one device.

        .PARAMETER Notes
        Optional free-text note (e.g. which host it came from, expiry observed).

        .EXAMPLE
        Add-StoredPRT -Identity 'asmith@contoso.onmicrosoft.com' -PRT $prtClear -SessionKey $clearKey -DeviceId jumpvm -Notes 'device owner = local admin on infradminsrv'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$PRT,
        [Parameter(Mandatory)][string]$SessionKey,
        [string]$DeviceId,
        [string]$Notes,
        [string]$StorePath = (Get-DefaultPRTStorePath)
    )
    try {
        $store = Get-PRTStoreData -Path $StorePath
        $key = Get-PRTStoreKey -Identity $Identity -DeviceId $DeviceId
        $entry = [PSCustomObject]@{
            identity    = $Identity
            deviceId    = $DeviceId
            clearPRT    = $PRT
            sessionKey  = $SessionKey
            notes       = $Notes
            lastUpdated = (Get-Date).ToString("o")
        }
        $store.identities | Add-Member -NotePropertyName $key -NotePropertyValue $entry -Force
        Save-PRTStoreData -Store $store -Path $StorePath
        Write-Host "Stored PRT under key: $key" -ForegroundColor DarkGray
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

function Get-StoredPRT {
    <#
        .SYNOPSIS
        Retrieve a stored PRT + session key, or list everything in the store.

        .PARAMETER Identity
        Look up by identity (and optionally -DeviceId to disambiguate).

        .PARAMETER Index
        Look up by index from -ListStore's table instead of -Identity.

        .PARAMETER ListStore
        Print every stored PRT (identity, device, notes, last updated) and exit.

        .PARAMETER ShowRoadtxCommand
        Also print a ready-to-paste roadtx prtauth command using this entry's
        PRT/session key - swap in -ClientId/-Resource before running it.

        .PARAMETER Clipboard
        Copy the PRT to the clipboard (session key printed separately, not
        clipped, so the two don't end up silently overwriting each other).

        .EXAMPLE
        Get-StoredPRT -ListStore

        .EXAMPLE
        Get-StoredPRT -Identity 'asmith@contoso.onmicrosoft.com'

        .EXAMPLE
        Get-StoredPRT -Index 0 -ShowRoadtxCommand
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByIdentity')]
    param(
        [Parameter(ParameterSetName = 'ByIdentity')][string]$Identity,
        [Parameter(ParameterSetName = 'ByIdentity')][string]$DeviceId,
        [Parameter(ParameterSetName = 'ByIndex', Mandatory)][int]$Index,
        [Parameter(ParameterSetName = 'List', Mandatory)][switch]$ListStore,
        [switch]$ShowRoadtxCommand,
        [switch]$Clipboard,
        [string]$StorePath = (Get-DefaultPRTStorePath)
    )
    try {
        $store = Get-PRTStoreData -Path $StorePath

        if ($ListStore) {
            $list = Get-PRTStoreEntryList -Store $store
            if ($list.Count -eq 0) {
                Write-Host "PRT store is empty ($StorePath)."
                return
            }
            $list | Format-Table -Property Index, Identity, DeviceId, Notes, LastUpdated -AutoSize -Wrap
            return
        }

        if ($PSCmdlet.ParameterSetName -eq 'ByIndex') {
            $key = Resolve-PRTIdentity -Store $store -Index $Index
        } else {
            if ([string]::IsNullOrEmpty($Identity)) { throw "Pass -Identity, -Index, or -ListStore." }
            $key = Get-PRTStoreKey -Identity $Identity -DeviceId $DeviceId
        }

        $entry = $store.identities.$key
        if (-not $entry) { throw "No stored PRT for key '$key'. Run -ListStore to see what's available." }

        Write-Host "Identity: $($entry.identity)" -ForegroundColor Cyan
        if ($entry.deviceId) { Write-Host "Device:   $($entry.deviceId)" -ForegroundColor Cyan }
        Write-Host "PRT:         $($entry.clearPRT)"
        Write-Host "Session Key: $($entry.sessionKey)"

        if ($Clipboard) {
            Set-Clipboard -Value $entry.clearPRT
            Write-Host "PRT copied to clipboard (session key was not - grab it separately above)." -ForegroundColor DarkGray
        }

        if ($ShowRoadtxCommand) {
            Write-Host "`nroadtx prtauth -c <clientId> -r <resource> --prt-init $($entry.clearPRT) --prt-sessionkey $($entry.sessionKey)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

function Remove-StoredPRT {
    <#
        .SYNOPSIS
        Delete one entry from the PRT store, by -Identity (+ optional -DeviceId) or -Index.

        .EXAMPLE
        Remove-StoredPRT -Index 1

        .EXAMPLE
        Remove-StoredPRT -Identity 'asmith@contoso.onmicrosoft.com'
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByIdentity')]
    param(
        [Parameter(ParameterSetName = 'ByIdentity', Mandatory)][string]$Identity,
        [Parameter(ParameterSetName = 'ByIdentity')][string]$DeviceId,
        [Parameter(ParameterSetName = 'ByIndex', Mandatory)][int]$Index,
        [string]$StorePath = (Get-DefaultPRTStorePath)
    )
    try {
        $store = Get-PRTStoreData -Path $StorePath

        if ($PSCmdlet.ParameterSetName -eq 'ByIndex') {
            $key = Resolve-PRTIdentity -Store $store -Index $Index
        } else {
            $key = Get-PRTStoreKey -Identity $Identity -DeviceId $DeviceId
        }

        if (-not $store.identities.PSObject.Properties[$key]) {
            throw "No stored PRT for key '$key'."
        }

        $store.identities.PSObject.Properties.Remove($key)
        Save-PRTStoreData -Store $store -Path $StorePath
        Write-Host "Removed: $key" -ForegroundColor DarkGray
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

Export-ModuleMember -Function Add-StoredPRT, Get-StoredPRT, Remove-StoredPRT
