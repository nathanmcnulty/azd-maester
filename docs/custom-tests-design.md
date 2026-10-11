# MCAT-003: optional custom-test package design

This is a source-only design assessment at catalog revision
`d232b49e5d727cb8427004bd798dcd6385ddedfe`, not implemented custom-test support.
[Issue #8](https://github.com/nathanmcnulty/azd-maester/issues/8) remains open as
the functional request and implementation gate. Its proposed `shared/custom-tests`
folder and storage-backed loading are not wired into the current runners.

The catalog's [migration contract](https://github.com/nathanmcnulty/azd-maester/blob/d232b49e5d727cb8427004bd798dcd6385ddedfe/README.md#L9-L43)
routes future implementation to the four standalone hosts. This document records
one common proposed contract; it does not change those host backlogs, the retained
legacy folders, component locks, IaC, permissions, defaults or runtime publishers.

## Current compatibility matrix

Fresh published source was inspected for all four standalone hosts. All use
pinned Maester 2.2.0 and locate embedded `maester-tests` first, then `tests` under
the selected module root. Absence of embedded tests fails rather than discovering
an ambient custom folder. None has a custom-test package input or an existing
`shared/custom-tests`/`Custom` tree. Retained catalog copies have the same selectors.

| Host and exact published revision | Actual selector / execution | Future integration boundary |
|---|---|---|
| [Automation e3fce00620e147fef4ae210007af923d9ad78ef4](https://github.com/nathanmcnulty/azd-maester-azureautomation/tree/e3fce00620e147fef4ae210007af923d9ad78ef4) | [Invoke-MaesterAutomationRunbook.ps1](https://github.com/nathanmcnulty/azd-maester-azureautomation/blob/e3fce00620e147fef4ae210007af923d9ad78ef4/scripts/Invoke-MaesterAutomationRunbook.ps1#L394-L449): verified module root, one selected path and existing report/upload flow | Explicit package selection before test invocation; preserve runtime package verification, job streams and report failure handling. |
| [Container 215d7bb703595ed460c9132014a6b9c5c503ace8](https://github.com/nathanmcnulty/azd-maester-containerappjob/tree/215d7bb703595ed460c9132014a6b9c5c503ace8) | [Invoke-MaesterContainerJob.ps1](https://github.com/nathanmcnulty/azd-maester-containerappjob/blob/215d7bb703595ed460c9132014a6b9c5c503ace8/scripts/Invoke-MaesterContainerJob.ps1#L324-L367): locked module tests, one path | Reviewed package included in an immutable image or verified at runtime; neither image publication nor a storage download is enabled here. |
| [Function 0c7462e942ac4d8b5bd4b8ac5a51d5fba7a6d94d](https://github.com/nathanmcnulty/azd-maester-functionapp/tree/0c7462e942ac4d8b5bd4b8ac5a51d5fba7a6d94d) | [MaesterTimerTrigger/run.ps1](https://github.com/nathanmcnulty/azd-maester-functionapp/blob/0c7462e942ac4d8b5bd4b8ac5a51d5fba7a6d94d/src/MaesterTimerTrigger/run.ps1#L387-L433): selected embedded path | Package selection must be bound to deployed code/runtime identity before timer execution; no new trigger or schedule. |
| [Azure DevOps 76ac648c7172981a22259f6d6fd701c2a085cb57](https://github.com/nathanmcnulty/azd-maester-azuredevops/tree/76ac648c7172981a22259f6d6fd701c2a085cb57) | [Invoke-MaesterAzureDevOpsRun.ps1](https://github.com/nathanmcnulty/azd-maester-azuredevops/blob/76ac648c7172981a22259f6d6fd701c2a085cb57/scripts/Invoke-MaesterAzureDevOpsRun.ps1#L455-L495): embedded tests and existing NUnit/report flow | Immutable package staged in the authorized pipeline workspace; retain pipeline target, result and cleanup semantics. |

The [Maester writing guide](https://maester.dev/docs/writing-tests/) describes
`Custom` and `.Tests.ps1` discovery, and the [update guide](https://maester.dev/docs/updating-tests/)
preserves `Custom` while replacing built-in suites. These describe upstream
behavior, not an Azure template packaging contract. The current command guide
describes a newer release; compatibility here is grounded in
[Maester 2.2.0 Invoke-Maester](https://github.com/maester365/maester/blob/c657a4b8a24267ccd795edb0c7db402e0d440e3b/powershell/public/Invoke-Maester.ps1#L118),
whose Path is a string and whose [test discovery is recursive](https://github.com/maester365/maester/blob/c657a4b8a24267ccd795edb0c7db402e0d440e3b/powershell/public/Invoke-Maester.ps1#L419-L445).
Do not assume multiple Path values or upgrade Maester/Pester as part of this feature.

New implementation and validation target PowerShell 7.6 or later only. Current
Automation/Function IaC still names 7.4; those existing settings are a rollout gap,
not a request to test or support that version. The Container image pin and
pipeline runtime also need explicit 7.6+ verification before rollout. Local
7.6.6 tests and Bicep compilation do not prove a hosted runtime's version or
regional provider support. Azure Automation 7.6 availability is unverified by
this assessment: future adoption must prove supported 7.6+ runtime configuration
for each selected host without a lower-version fallback. This assessment leaves
all existing runtime metadata untouched.

## Proposed default-off package contract

Enablement would require an explicit host parameter and an approved immutable
package reference. Default off must continue running the unchanged embedded
suite, even if custom-looking files, environment variables or blobs exist.
Enablement without a complete valid package must fail before execution; it must
not silently fall back to embedded-only success.

A future versioned manifest should identify the package, source repository and
immutable revision, exact archive SHA-256 and length, compatible Maester version,
PowerShell 7.6+ requirement, and a closed file inventory with normalized relative
paths, lengths and SHA-256 values. It should identify test IDs and reviewed
permission requirements separately from file integrity. A branch, latest blob,
ETag alone or display catalog metadata is not an immutable code identity.

Packaging would occur in the canonical standalone source, using an explicitly
selected input directory, not an implicit shared folder search. Reject duplicate
or case-colliding paths/IDs, absolute/UNC/drive paths, traversal, encoded path
escapes, links/reparse points, unexpected files, archive expansion/size limits and
an inventory mismatch. Review allowed `.Tests.ps1` files and their exact helper/
markdown dependencies; do not treat an extension check as a code sandbox.
Verify archive identity and all extracted bytes before discovering tests or
loading helpers. Close the selection-to-execution race with a private immutable
staging directory and recheck the selected inventory immediately before invocation.

For Maester 2.2.0, a private composite staging root can hold the pinned built-in
suites plus reviewed `Custom` files, then supply that single root as Path. Do not
modify the integrity-locked module directory or overwrite upstream tests. Reject
collisions with built-in paths/test IDs, and retain upstream failure, tagging and
report semantics. Selection and discovery need separate tests from actual custom
execution, report generation and live-service acceptance.

## Storage, identity and permissions

Prefer deployment-time inclusion in a hash-bound code/image/pipeline package
where the host supports it. If runtime storage delivery is selected, bind it to
the explicit deployed storage account/container/resource IDs and tenant/
subscription/host identity, plus an owned package prefix and content hash. Use
the host's existing authorized data-plane route; additional access, if required,
must be an explicit optional permission delta scoped to that exact package.
Do not assume access to report storage grants permission to fetch executable code.

No authentication change, Graph scope, role assignment, consent or grant follows
from enablement or manifest metadata. Custom tests execute with the host's
privileges and can call arbitrary PowerShell APIs. Hashes establish identity, not
safety, a read-only guarantee or confinement. Each approved package needs code
review and an explicit tenant/service permission assessment; unknown requirements
are gaps. Tests needing new write permissions or interactive authentication must
remain outside an unattended baseline until separately authorized and reviewed.
Do not introduce device-code authentication or automatic permission discovery.

Use an owned immutable package prefix, not issue #8's suggested blanket blob
wipe on `azd up`. Updates should select a new package hash without deleting report
history, unrelated blobs, built-in tests or another deployment's files. Rollback
selects a previously reviewed package hash or disables the feature. Storage write/
delete and runtime delivery proof remain separate authorized implementation gates.

## Receipt, output and rollout gates

Keep host run/report receipts solution-owned. Future receipts can add package ID,
revision, archive/file-inventory hashes, selected host/target identity, verification
and discovery states, and exact executed test IDs/counts. They must distinguish
package verified, tests discovered, tests executed, report generated, report
uploaded and recipient-visible delivery. Do not persist package code, access
tokens, SAS URLs, raw provider errors or secret test output in a provenance receipt.
Existing report redaction needs review for each custom package; no blanket secrecy
or delivery claim is made here.

Implementation acceptance, to be tracked in host backlogs under open issue #8:

1. Default-off baseline is byte/behavior compatible. A package cannot be selected
   from ambient files or moving network references. All four adapters preserve
   deployment target/ownership and existing failure/receipt contracts.
2. Deterministic negative fixtures cover foreign tenant/host/storage identity,
   wrong revision/hash, path/link/collision/expansion limits, changed bytes after
   verification, unexpected permissions and missing package input; no custom
   code runs when verification fails. A positive inert package proves selection
   and discovery independently of a live tenant.
3. Review actual Maester 2.2.0 execution and reporting with a deliberately inert
   package first, on PowerShell 7.6+. Then independently review one selected host
   before a separately authorized disposable live pilot. Do not run all four
   hosts, provision storage, publish images, change schedules or send results from
   this design assessment.
4. Review effective host permissions and each tenant-specific custom test before
   live execution. Prove package transport, actual execution/report integration,
   target identity, cleanup and rollback separately. Expand to remaining hosts
   only after their own adapter/evidence review; no production rollout is inferred.

This assessment may complete MCAT-003's feature-design acceptance. The functional
feature remains unimplemented; issue #8 stays open and future implementation
belongs in the canonical host backlogs. Neither a completed assessment nor a
successful local suite authorizes deployment or custom code execution.

## Assessment validation

Private hash-bound captures preserve the exact four standalone selectors,
backlogs, READMEs and complete trees, plus upstream Maester 2.2.0 source. Isolated
actual selector AST proofs test preferred embedded selection, fallback selection
and refusal with only ambient custom tests for all four hosts (12 cases), without
invoking Maester, executing placeholder test code or authenticating. These prove
the current baseline, not the proposed package verifier or feature.

The existing registered offline validation remains the root plus all four host
Pester suites, Bicep 0.46.1 builds of all four templates, and repository-wide
PowerShell parsing. No new tests merely restate this document. Current-source
results and exact hashes are retained outside public Git for independent review.
