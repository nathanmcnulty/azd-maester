# Optional Maester report viewers

Assessed 2026-10-15 against catalog revision
`ba417deae1664e89f996233ddd0e3ced33bab2c4` and open issues
[#5](https://github.com/nathanmcnulty/azd-maester/issues/5) and
[#4](https://github.com/nathanmcnulty/azd-maester/issues/4).
This completes MCAT-004/005 discovery; neither viewer is implemented.
The issues contain truncated prices and damaged configuration examples.

## Scope and compatibility

Implement in the canonical hosts, with this catalog tracking coordination:

| Retained folder | Canonical implementation repository |
| --- | --- |
| `container-app-job` | [azd-maester-containerappjob](https://github.com/nathanmcnulty/azd-maester-containerappjob) |
| `automation-account` | [azd-maester-azureautomation](https://github.com/nathanmcnulty/azd-maester-azureautomation) |
| `function-app` | [azd-maester-functionapp](https://github.com/nathanmcnulty/azd-maester-functionapp) |

Do not add features to retained folders. Azure DevOps is outside these issues'
three-host scope and needs its own publisher task. Each canonical host has separate
implementation tasks; MCAT-009/010 coordinate their delivery and qualification.
Preserve `-IncludeWebApp` and its App Service behavior. Add
`-IncludeContainerWebApp` and `-IncludeStaticWebApp` as mutually exclusive options.
No flag means no viewer. Reject conflicts before writes, normalize to one internal
provider value, and never silently migrate an existing environment.

Shared standards/components belong in `azd-reference`. Preserve existing hook and
report-web-app locks. Any new shared runtime needs real host integrations, reviewed
versioned releases, immutable revisions and hashes. Vendor into each host; never
fetch another repository at deployment time. Custom domains are optional, require
DNS/certificate ownership receipts, and are not an authentication boundary.

## Publication contract

Existing runners produce `latest/latest.html` and private history. Add a dedicated
private viewer-projection container, separate from archives. Inventory actual
runner grants; do not claim current account-wide permissions are blob-scoped.
Write immutable HTML and a manifest under a run/version identifier. Bind tenant,
environment, run ID, byte length and SHA-256. Publish a small `latest` pointer last,
with an ETag condition and ordered generation rule so an old concurrent run cannot
replace a newer projection. Read exactly the pointer's immutable objects; verify
hashes/bounds and retry a changed pointer within a fixed budget. Independently
overwritten HTML and manifest are not an atomic snapshot.

Only a bounded HTML projection and explicitly qualified assets enter the viewer.
Reject traversal, escaping links, unexpected files, excessive sizes and report-
supplied URLs/configuration. Qualify actual Maester scripts/styles and external
assets; do not assume self-contained HTML. Reports cannot supply deployment code,
auth config or executable publication scripts.

## Caddy on Container Apps

Use separately digest-pinned Caddy and sync-worker images with reviewed source,
SBOM and provenance. The worker uses an explicitly selected managed identity to
read only the projection container, downloads fixed pointer/objects into bounded
ephemeral staging, and atomically replaces the verified local HTML. Caddy mounts
it read-only, disables browsing/admin ingress and performs no arbitrary proxying.
Refreshing reports needs no new revision or runner control-plane permission.
Image/config changes use a separately reviewed Container App revision.

Containers in the same app are not an identity boundary: assume both can use the
app's available managed identities. Grant only projection read access, never
archives, Graph, storage keys or resource writes. Qualify any separate private-
registry pull identity against its registry RBAC/ABAC mode and lifecycle settings.
Use a normal worker container; do not assume init-container identity support.

Confidential reports always require HTTPS plus Entra authentication and audience
authorization. Stable `Microsoft.App/containerApps/authConfigs@2026-07-01` supports
`defaultAuthorizationPolicy.allowedPrincipals.groups/identities`. Choose one
explicit policy with exact tenant issuer, audience and approved group IDs. Missing,
malformed and overage claims must deny; prove actual service behavior. Revision,
default and custom hostnames, extra ports and forged identity headers must not
bypass protection. Do not expose reports while auth configuration is incomplete.

Empty/invalid startup content is unavailable. On refresh failure retain only a
bounded last-known-good projection, show staleness to authorized readers, and
apply an explicit maximum stale age. Probe readiness without exposing tenant or
report data. Bound polling, downloads and cache size. Scale-to-zero requires fresh
download/cold-start qualification; minimum replicas zero versus one is an explicit
latency/cost setting. Roll back image revisions and report pointers separately.

## Static Web Apps Standard

Require Standard, a custom tenant-specific Entra provider, and authorization for
HTML, assets and fallback paths. Tenant sign-in alone is insufficient; app
assignment requirements also have a Global Administrator exception. SWA roles
are not Entra groups. A candidate is a `Report.Reader` app role mapped to a SWA
role by a small `rolesSource` function using only trusted platform tenant/provider/
role claims. Deny unexpected or missing claims; add no broad runtime Graph read
for role mapping. Microsoft labels function-based role assignment preview: record
support implications and qualify them before enabling this option. Invitations
are not a silent replacement for group authorization or membership revocation.

For workforce end-user sign-in, SWA documents a dedicated user-assigned managed
identity/federated credential alternative to the Entra client secret. This does
not authenticate report publication. Keep its identity/trust receipt separate
from the publisher and never attach that identity to unrelated resources.

A deployment token can replace the artifact, including auth config and API code.
Treat its holder as a privileged site publisher, not a content-only writer. Keep
it out of Maester runners. A separate trusted publisher reads the projection,
copies only approved report bytes into a fixed artifact, and verifies reviewed
config/function/image hashes. It retrieves the one deployment-token secret from
a protected store for the deployment process only. Reject runner-provided config,
scripts, archive paths and deployment URLs. Prevent token disclosure in logs,
source and artifacts; do not assume short-lived or secretless deployment support.

Failed deployment retains the previous qualified artifact. Record artifact hashes,
deployment IDs, exact site/environment IDs and token-rotation receipts. Test reset
and update of the protected token reference. Protect every preview environment
equivalently or disable it; never stage real reports in an unauthenticated site.

## Permissions and costs

| Principal | Proposed narrow boundary |
| --- | --- |
| Runner | Collection grants unchanged; new projection writes use Storage Blob Data Contributor at that container if needed |
| Caddy app/worker | Storage Blob Data Reader at projection container; no archives, Graph, keys or resource writes |
| SWA publisher | Projection reader plus the one deployment-token secret; token grants site deployment authority |
| Deployment operator | Exact owned app/FIC/auth configuration, audience assignments and resource operations |

Record exact actions/scopes in host permission manifests before grants. Metadata
is not consent or proof of current privilege. No runner/viewer needs subscription
Owner. Delete only recorded owned resources; retain adopted resources, shared
storage and user-owned DNS. Entra objects, FICs, secrets and assignments need
separate ownership-aware cleanup.

Use dated regional pricing/calculator evidence, explicit workload assumptions,
currency and uncertainty. Separate estimates to avoid double counting:

- ACA Consumption: billable active/idle vCPU-seconds and GiB-seconds at their rates,
  plus requests after applicable allowances; include both containers, polling,
  storage operations, image pulls, transfer and logs.
- ACA Dedicated: allocated profile vCPU/GiB time at the published rates and applicable
  management charges, plus storage/transfer/logs; do not add Consumption compute again.
- SWA: Standard charges, applicable bandwidth excess, publisher/API execution,
  secret storage and projection operations. Identity does not remove these costs.

## Acceptance and rollout

Offline implementation does not require invented product approval. Prove
exclusive/default-off flags, unchanged App Service behavior, bounded ETag/snapshot
ordering, content rejection, narrow permissions, image/config hashes, source locks
and owned rollback. Compile each host and run its registered validations. Fixtures
must reject invalid/missing/overage claims, forged headers and publisher attempts
to alter auth config; they are not native-service proof.

Use PowerShell 7.6+. Catalog validation pins Pester 5.7.1 and runs:
`Invoke-Pester -Path ./tests,./automation-account/tests,./container-app-job/tests,./function-app/tests,./azure-devops/tests -CI`.
Its workflow compiles all four retained `infra/main.bicep` templates with Bicep
0.46.1 and parses PowerShell. Canonical hosts retain their own registered workflows;
record their exact commands/revisions with implementation evidence. This discovery
changes documents only, so schema/render checks and hosted repository gates suffice.

Qualify one provider/host in the authorized lab, then all three hosts. Before writes
verify exact tenant/subscription, owned resources, audience group and test users;
reuse normal cached/broker/browser auth. Prove allowed access and rejection of
anonymous, unassigned and other-tenant users across every URL and asset path.
Verify report bytes, staleness, concurrency, cold start, applicable token/config
rotation, rollback and exact-resource cleanup. Permission and consent changes must
fit the session's authorization and reviewed target scope; backlog metadata grants
no authority over unrelated targets. Retain failed evidence and retry in a new
directory. Upload acceptance and green tests do not prove human-visible delivery.

## Official sources checked 2026-10-15

- [SWA custom auth, FIC and roles](https://learn.microsoft.com/en-us/azure/static-web-apps/authentication-custom)
- [SWA deployment tokens](https://learn.microsoft.com/en-us/azure/static-web-apps/deployment-token-management)
- [Entra app assignments](https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users)
- [ACA auth configuration](https://learn.microsoft.com/en-us/azure/templates/microsoft.app/containerapps/authconfigs)
- [ACA Entra auth](https://learn.microsoft.com/en-us/azure/container-apps/authentication-entra)
- [ACA identities](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity)
- [ACA pricing](https://azure.microsoft.com/en-us/pricing/details/container-apps/)
- [SWA pricing](https://azure.microsoft.com/en-us/pricing/details/app-service/static/)
