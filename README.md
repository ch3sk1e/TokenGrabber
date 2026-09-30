# TokenGrabber

A pair of PowerShell modules for Entra ID token wrangling during Azure AD
attack-path work (built for CARTP-style engagements): mint tokens for
multiple resource audiences in one call, keep refresh tokens and cached
access tokens in a local store so you never re-authenticate for the same
identity twice, and separately track clear PRTs + session keys for
`roadtx`-style primary-refresh-token abuse.

Two independent modules, deliberately not sharing code or a store file:

- **`Get-MultiToken.psm1`** - identity seeding (credential login-form
  emulation, device code, client credentials, or importing a refresh token
  minted elsewhere) plus a persistent access-token store.
- **`Get-PRTStore.psm1`** - a standalone store for clear PRT + session key
  material, because a PRT is a different class of secret (mints tokens for
  *any* client via `roadtx`, not one resource-scoped bearer token).

## Why

Existing tooling (`Get-AccessToken.ps1` from AADInternals, TokenTactics2,
etc.) does one flow at a time and doesn't remember what it already minted.
Mid-engagement you're usually juggling several identities against several
resources (Graph, ARM, legacy AAD Graph, Key Vault, Storage) through several
client IDs, and re-typing credentials or re-running a device code flow for
every resource gets old fast. TokenGrabber seeds an identity once, mints
against however many resources you ask for, and persists refresh tokens so
later calls for the same identity are just a store lookup.

## Install

```powershell
Import-Module .\Get-MultiToken.psm1
Import-Module .\Get-PRTStore.psm1
```

## Get-MultiToken.psm1

```powershell
# Credential-based login (scripted emulation of the real sign-in form -
# GetCredentialType -> form POST -> KMSI -> auth code -> token exchange.
# Full Conditional Access evaluation applies; this is not an MFA bypass.)
Get-MultiToken -UserName 'jdoe@contoso.onmicrosoft.com' -Password 'P1aceholderPass!23' `
    -ClientId teams -Resources msgraph,arm,aadgraph

# Device code flow - use this when MFA is actually enforced
Get-MultiToken -DeviceCode -ClientId azurecli -Resources msgraph,arm -TenantId 'contoso.onmicrosoft.com'

# App-only, client credentials grant
Get-MultiToken -ClientCredentials -ClientId <appId> -ClientSecret <secret> `
    -TenantId 'contoso.onmicrosoft.com' -Resources arm

# Import a refresh token obtained elsewhere (e.g. an ESTSAUTH/ESTSAUTHPERSISTENT
# cookie converted to an RT via TokenTactics2) - redeemed and stored like any
# other identity
Get-MultiToken -RefreshToken $stolenRt -ClientId azurecli -Resources msgraph,arm,vault

# Resume - no fresh credentials needed, uses the stored refresh token
Get-MultiToken -Identity 'jdoe@contoso.onmicrosoft.com' -Resources vault

# Which client gives the broadest access to a resource?
Get-MultiToken -Sweep -Resources msgraph -UserName 'jdoe@contoso.onmicrosoft.com' -Password 'P1aceholderPass!23'

# Inventory
Get-MultiToken -ListStore
Get-MultiToken -ListClients
Get-MultiToken -ListResources
```

Pull a token back out later without re-minting:

```powershell
Get-StoredToken -Identity 'jdoe@contoso.onmicrosoft.com' -Resource arm
Get-StoredToken -Index 0 -Resource arm -Clipboard   # -Index from -ListStore's leftmost column
Remove-StoredToken -Index 2
```

### Config files

Same folder as the module, override with `-ResourceAliasPath` / `-KnownClientsPath`:

- **`resource-aliases.json`** - short name -> resource URI (`arm`, `msgraph`,
  `aadgraph`, `vault`, `storage`, `outlook`, ...).
- **`known-clients.json`** - short name -> `{clientId, displayName,
  redirectUri, notes}` (`teams`, `intune`, `office`, `azurecli`,
  `azurepowershell`). Notes capture what each client is pre-authorized for
  and what it's good for (e.g. `azurecli` for directory-admin-flavored Graph
  scopes and broad Storage access, `office` for legacy AAD Graph / principal
  ObjectId resolution). `-ClientId` also accepts a raw client_id GUID.

`-ClientId` is never silently swapped based on the resource (unlike the
original `Get-AccessToken.ps1`, which force-switches to Intune Company
Portal whenever `-Resource` is ARM) - you get a warning instead if a pairing
looks unusual, and the client you asked for is the client you get.

## Get-PRTStore.psm1

For clear (decrypted) PRTs + session keys pulled via
`sekurlsa::evasive-cloudap` / `dpapi::cloudapkd` or similar, so you don't
have to re-extract every time you want to reuse one with `roadtx`.

```powershell
Add-StoredPRT -Identity 'asmith@contoso.onmicrosoft.com' -PRT $prtClear -SessionKey $clearKey `
    -DeviceId jumpvm -Notes 'device owner = local admin on target host'

Get-StoredPRT -ListStore
Get-StoredPRT -Identity 'asmith@contoso.onmicrosoft.com' -ShowRoadtxCommand
Get-StoredPRT -Index 0 -Clipboard

Remove-StoredPRT -Index 1
```

`-ShowRoadtxCommand` prints a ready-to-paste
`roadtx prtauth -c <clientId> -r <resource> --prt-init ... --prt-sessionkey ...`
command using the stored entry.

## Store files

> [!WARNING]
> Both modules write their store next to the module (`token-store.json`,
> `prt-store.json`) unless you pass `-StorePath`. These files hold live
> credential material (refresh tokens, access tokens, clear PRTs, session
> keys) - treat them the same as any other loot, keep them out of version
> control (already covered by `.gitignore`), and delete them when the
> engagement ends.

## Credits

The credential-based login flow in `Invoke-CredentialLogin` (GetCredentialType
-> form POST -> KMSI handling -> auth code -> token exchange) is adapted from
[`Get-AccessToken.ps1`](https://github.com/Gerenios/AADInternals) in
**AADInternals** by Dr. Nestori Syynimaa ([@DrAzureAD](https://github.com/Gerenios)).

The refresh-token-to-multi-resource redemption pattern and general
multi-audience token workflow were informed by
[**TokenTacticsV2**](https://github.com/f-bader/TokenTacticsV2) (Fabian Bader),
a fork of the original **TokenTactics** by Steve Borosh and Bobby Cooke.

TokenGrabber itself is a from-scratch reimplementation built around a
persistent local store and a `-Resources`/`-ClientId` multi-audience model,
not a copy of either project - but the underlying OAuth mechanics owe credit
to both.

## Disclaimer

For use in authorized security assessments and lab environments (e.g.
Altered Security's CARTP) only. You are responsible for using this against
systems you're authorized to test.
