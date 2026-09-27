# Microsoft, on-prem AD and hybrid fleets

Treat directory inventory, endpoint inventory and actual usage as different evidence. AD objects or Entra applications alone do not prove AI use. Hybrid identity joins are not automatic: AD objectGUID/SID, Entra object IDs and agent device IDs may differ. Preserve their provenance and validate any mapping before attributing activity to a person.

## On-prem Active Directory

Run `scripts/Export-ActiveDirectory.ps1` on a management host with RSAT ActiveDirectory and an account authorized to read the chosen OUs. Domain Administrator is not required by this script. Each `-SearchBase` must be an OU distinguished name; domain-root queries are rejected. The script calls Get-ADComputer/Get-ADUser and performs no directory mutations.

```powershell
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -WhatIf
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export'
```

Each run creates a private subdirectory containing API-compatible `{events:[...]}` batches of at most 500. Fields include observation timestamp, stable GUID/SID identity and optional user/computer names. No passwords, email addresses, group memberships, recovery keys or broad attribute dumps are collected.

For upload, configure an HTTPS origin and provide the collector key via `AGENT_API_KEY_FILE` or `AGENT_API_KEY` in the current process. Prefer a protected file.

```powershell
$env:AGENT_API_KEY_FILE = 'C:/Protected/OpenShadowAI/collector-key.txt'
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -Upload -ApiUrl 'https://ai-inventory.example.com' -TenantId 'default'
```

TLS certificate validation remains enabled and redirects are rejected. Failed uploads retain their batches; retry the original JSON with unchanged event IDs. A new export is a new observation. Restrict export access and retention because identifiers and account names remain sensitive organizational data.

Source: [Microsoft Get-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer) and [Get-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser). Static checks are provided; live AD behavior and permissions require a pilot.

## Entra ID

For console sign-in and account provisioning, use the separate [OIDC/SCIM guide](sso-scim.md). The collector below inventories applications; its Graph permissions and client secret do not enable console SSO. Synced on-prem AD accounts can access the console through Entra after deliberate provisioning and identity mapping.

Create a dedicated application registration for the collector. Provision its client secret separately into `secrets/entra_client_secret.txt`; the bootstrap does not invent a usable Microsoft credential. Protect it with the same directory permissions as other deployment secrets.

Set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_POLL_INTERVAL_SECONDS` (minimum 60) in your private `.env`. Enable the `entra` Compose profile.

The service-principal inventory uses Microsoft Graph application permission `Application.Read.All`, with administrator consent. Delegated-grant collection is disabled by default (`ENTRA_COLLECT_GRANTS=false`). Enabling it adds `Directory.Read.All` for the delegated-permission-grants endpoint; obtain consent only after reviewing that broader permission.

```bash
docker compose --profile entra up -d --build entra-collector
docker compose logs --tail 100 entra-collector
```

These are inventory/permission signals. They do not prove calls to a model or count tokens. Live tenant, throttling and permission validation remain operational acceptance steps. See [Graph servicePrincipals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0) and [oauth2PermissionGrants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0).

### Required AI application mapping

The shipped catalog currently has no built-in OAuth application-ID mappings. The collector inventories service principals and optional grants, but does not automatically classify their display names as AI. To enable AI matching, an administrator must review the application and add its verified Graph `appId` to a catalog signature. Do not substitute the tenant-specific service-principal object ID.

See `catalog/local/entra-app.yaml.example`: it contains an explicitly fake UUID and is not loaded by default. Replace the sample with your reviewed mapping, save a private `.yaml` file under `catalog/local/`, and run `docker compose run --rm api python -m shadai.cli sync-catalog`. A custom ID creates an additional catalog item; reusing an existing ID replaces its YAML definition, so preserve the other reviewed signatures. A match still indicates application inventory or permission, not observed AI calls.
## GPO pilot deployment

The repository supplies `scripts/Install-AgentWindows.ps1`, an operator-run **local** installer. It does not create, link or edit a GPO. Build an agent wheel, approve its dependencies in an offline wheelhouse, record SHA256, and distribute Python through your normal software-management process.

The scheduled task runs as SYSTEM, so the installer refuses anything a standard user could alter beforehand or afterwards:

- The install directory (default `%ProgramData%\OpenShadowAI`) must not exist. It is created with a protected ACL (SYSTEM and Administrators only, owner Administrators); an existing directory is never reused. After installation every file is reset to that ACL and owner, then checked.
- The Python installation used for the virtual environment (for example `C:\Program Files\Python313`) and the wheelhouse, including every wheel in it, must be owned by SYSTEM, Administrators or TrustedInstaller and writable only by them.
- No parent directory of these paths may be a junction or symbolic link, or be renamable or re-permissionable by another principal.
- The agent wheel is copied into the protected directory and its SHA256 is checked on that copy before installation.

A per-user Python installation or a wheelhouse under a default `C:\` or `%ProgramData%` subfolder fails these checks, because authenticated users can write there. Prepare a protected wheelhouse first:

```powershell
$wheelhouse = Join-Path $env:ProgramData 'OpenShadowAI-wheelhouse'
New-Item -ItemType Directory -Path $wheelhouse | Out-Null
icacls $wheelhouse /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
icacls $wheelhouse /setowner '*S-1-5-32-544'
# Copy the approved wheels in, then re-apply ownership to them.
icacls $wheelhouse /setowner '*S-1-5-32-544' /T
```

1. Choose a pilot OU and security group, document collection, and approve endpoint access.
2. Provision the API key separately using a protected management channel; do not put it in SYSVOL or a broadly readable GPO script.
3. Review/sign the install script and its generated runner according to your PowerShell policy.
4. Test the script with `-WhatIf` on one machine, then install with explicit local administrator approval.
5. Start the registered task, confirm HTTPS ingestion and inventory scope, then stage a GPO startup script using your normal change process.
6. Define rollback: stop/unregister `OpenShadowAI-Agent`, remove its approved install directory and revoke/rotate the key if needed. Preserve evidence required by policy.

```powershell
./scripts/Install-AgentWindows.ps1 -Python 'C:/Program Files/Python313/python.exe' -WheelPath $approvedWheel -WheelSha256 $approvedHash -Wheelhouse $wheelhouse -ApiKeyFile 'C:/Protected/collector-key.txt' -ServerUrl 'https://ai-inventory.example.com' -WhatIf
```

Running as SYSTEM may not reveal every user's browser profile. Inventory coverage varies by OS, permissions and collector. Package signing, restart behavior, upgrade/uninstall and rollout through GPO remain fleet acceptance tests.

## Intune, Configuration Manager and other operating systems

For Intune Win32 apps or Configuration Manager applications, package the approved offline wheelhouse and installer, define a detection rule for the installed version, and supply secrets through a protected channel. Detection/remediation scripts, MSI packaging, signed releases and automated lifecycle handling are not delivered yet.

For Linux/macOS, install the agent in a dedicated virtual environment, set `SHADAI_AGENT_CONFIG`, `AGENT_API_KEY_FILE` and optionally `SHADAI_CA_BUNDLE`, then invoke `python -m shadai_agent.main`. Start interactively on a test endpoint before configuring a systemd/launchd service with your existing device-management tools. Service templates, notarization and fleet operation require validation.

## Other directories

Native inventory collectors for LDAP, Okta and Google Workspace are planned. Authorized adapters can send scoped inventory through the [generic event contract](collectors.md). Generic OIDC sign-in and a SCIM console-provisioning subset are available separately; validate your provider against the [supported contract](sso-scim.md#supported-subset). Neither AD export nor Entra inventory automatically enrolls devices or configures other infrastructure.
