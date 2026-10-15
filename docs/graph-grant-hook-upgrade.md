# Tenant-bound Graph grant hook upgrade

The four retained host layouts now consume `maester-azd-hooks` 0.1.7 from
[`azd-reference@8e1f48cd623405caff2975948f1d28f3ec8104f7`](https://github.com/nathanmcnulty/azd-reference/commit/8e1f48cd623405caff2975948f1d28f3ec8104f7).
Each nested component lock records that immutable source revision and every
managed file's SHA-256. The root remains a legacy wrapper; the standalone host
repositories remain the canonical deployment paths.

The retained `shared/scripts/Grant-MaesterGraphPermissions.ps1` is updated to
exactly the same source bytes. Its older sibling setup helper already supports
explicit tenant forwarding, and is intentionally retained. The regression suite
runs the real grant and REST helper for all five layouts with synthetic token and
HTTP responses, without calling Azure or Microsoft Graph.

## Grant behavior

Every Graph request uses the selected tenant, including service-principal lookup,
assignment pagination, creation and exact assignment readback. Existing roles are
preserved, and a grant on a later page is not posted again. Unsafe, repeated,
excessive or incomplete continuation fails before mutation. Invalid or disabled
requested application roles fail before the first write. The requested Minimal,
Extended, optional Mail.Send and explicit role sets are unchanged.

## Explicit compatibility delta from 0.1.0

This is a reviewed component migration, rather than modified bytes falsely
labelled as the old immutable 0.1.0 release. In addition to the grant fix, these
four previously published helper changes are adopted:

- `Get-ManagedIdentityPrincipal.ps1` retries identity propagation up to 12 attempts
  with five-second waits. Its arguments and returned principal ID are unchanged.
- `Maester-SetupHelpers.psm1` adds an optional subscription selector for Azure CLI
  tokens. It chooses subscription when provided, otherwise tenant, never both.
- `Maester-UpWizard.psm1` requires a valid non-empty security-group GUID when the
  optional Web App is enabled. Interactive users can correct it or skip the Web
  App; a disabled Web App does not validate or look up that group.
- `Maester-PreDownCleanup.psm1` retries exact Azure DevOps service-connection
  deletion while pipeline cleanup converges, and deletes a repository only when
  `AZDO_REPOSITORY_CREATED=true` explicitly records creation ownership.

**Legacy Azure DevOps cleanup:** this legacy setup does not record that creation
flag. Its repository is therefore preserved during teardown after this upgrade.
This is deliberately conservative; do not infer ownership or add a creation flag
merely to enable deletion. Review any retained repository separately. The upgrade
includes a synthetic cleanup test proving no repository DELETE is issued without
the flag.

`Maester-Helpers.psm1`, `Maester-PreProvision.psm1`, and `Maester-PreUp.psm1` remain
byte-identical to the prior locked copies. Infrastructure, runtime package locks,
and runtime permissions are unchanged. Offline regression results do not replace
separately authorized live tenant qualification.
