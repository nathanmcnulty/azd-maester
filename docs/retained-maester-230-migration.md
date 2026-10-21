# Retained Maester 2.3 migration: assessment runtime slices

These are bounded source slices of issue #41, not completion of the
four-host or reviewed-consent migration. New deployments still belong in the
standalone templates. No native deployment or authentication is qualified here.

## Dependency and source record

The integration preserves both existing catalog drafts:

- Runtime #39: `ac43ace6c30f7a77d0a02bd7b1e207564eee3054`.
- Drift/catalog #40: `a5003aecf892186efcb47cd7489495b2d0783fc0`.

The only integration conflict is the validation dependency step; the stricter
#40 PowerShell 7.6 guard and pinned Pester 6.2.0 import are retained. Neither
upstream draft is modified or considered merged by this local integration.

Function package lock, timer, assessment evidence module and focused tests are
exact copies from standalone Function draft #44 at
`a3f9bc84c9b7551d34734d2a632aa5ea14d19fe2`. The package is Maester 2.3.0, SHA-256
`95F720822D04271F5E15F4665BC017111DC72E17B97E5D0525CB4EC2FF5BD0B0`.
The timer includes the reviewed Blob `x-ms-date` header fix. Current runtime
contract records identify that exact source; replaced historical source records
remain under `previousSource`, rather than being silently rewritten.

## Changed behavior

The timer imports the locked 2.3.0 module and requests structured assessment
results plus JUnit output. It requires a nonempty, correctly bound HTML report,
consistent counts, executed core checks, and no unexplained runtime/setup errors.
Policy findings remain findings, not transport or assessment-execution failures.
Drift remains disabled before discovery and inherited drift state is restored.
Telemetry and automatic version checks are disabled for this invocation.

The Function packager already stages the entire `src` tree, including the new
assessment evidence module. Existing catalog target binding, private report
publication, validation trigger, request/receipt semantics, FC1/B1 topology,
identity behavior and deployment hooks are preserved. The runtime change grants
no permission and creates no new resource or schedule.

## Remaining acceptance

- Complete the retained Container host/delivery migration and migrate Azure DevOps
  with their own dependency reconciliation; do not copy unrelated enabled-drift code.
- Adopt reviewed hook/coordinator consent in all four hosts and `shared/scripts`.
  The existing retained hooks and their Extended/default permission behavior are
  unchanged by this runtime-only slice. Do not infer consent readiness from a
  passing offline Function test.
- Complete registered all-host checks, pinned Bicep compilation and real-package
  compatibility qualification for each changed runtime; report results separately
  from hosted checks and platform skips.
- Independently review each final tree, publish only after approval, and verify
  exact-head hosted checks. Issue #41 remains open.
- Separately qualify native Function deployment, bundled-package loading,
  managed-identity effective access, private report retrieval, request-bound validation receipts,
  rollback and cleanup with exact approved targets. No source test proves these.

The standalone-style real-package compatibility script is an explicit local
qualification command, not automatically discovered by the existing hosted
`*.Tests.ps1` suite. Do not report hosted real-package execution unless its
separate command was actually run.

## Automation follow-through

The Automation runbook embeds the exact pure assessment gate and invocation
configuration/boundary from standalone draft #49 at
`0385b7973435a75922f9ad93b7ac8e053092d2a2`. The file remains a maintained catalog
copy, not an exact whole-file copy: existing imports, managed-identity setup,
schedule ownership, private publication and validation interfaces remain intact.
The runtime-contract lock preserves the original source record and records this
scoped adoption separately. The Blob date header follows reviewed #50.

Both the Bicep package pin and runbook byte verifier use the same Maester 2.3.0
package/hash above. The immutable seed is upstream commit
`7413c42d3fcc724dfea94d2726e690ddd364d914`, SHA-256
`87CEB74D50309360C592816BFC963A6D370B66C51AE71D45A01117651BF7F5A8`.
It remains unscheduled; postprovision must publish the local maintained runbook
before creating the schedule association. No role, schedule or topology is added.

Emitted invocation errors fail closed while internally handled assertion/probe
errors do not falsely reject legitimate policy findings. The gate still checks
structured test errors, core execution, JUnit accounting and the exact report.
The explicit local real-package harness covers six synthetic modes: policy,
runtime error, setup error, after-all error, discovery error and core skipped.
Diagnostic-only projection tests from standalone #50 are excluded because this
slice does not adopt its private diagnostic artifact feature.

The existing catalog Automation validator remains job-status/stream-based.
It does not gain the standalone job-content-bound assessment receipt protocol;
passing offline tests is not end-to-end job-bound assessment verification.
Reviewed setup-consent, runtime-only validation modes, new failure diagnostics,
and native host acceptance remain separate work. Existing configured inline mail
behavior remains opt-in through its prior setting; delivery is not proven.

## Container assessment follow-through

The retained Container runner now pins the reviewed Maester 2.3.0 package and
uses the same exact pure assessment gate as the reviewed retained Function copy
(original standalone Function a3f9bc84c9b7551d34734d2a632aa5ea14d19fe2).
The invocation follows standalone Container #52 at
939b52eb0299ddb7171b1aaf4fb26d8c0a306af7: structured output, JUnit, exact
assessment.html binding, core-test execution and classified failures. A genuine
policy finding is accepted; invalid/incomplete execution is rejected before
report storage publication. Drift is excluded before discovery and inherited
MAESTER_FOLDER_DRIFT is cleared only during invocation and restored in finally.
The existing Azure Files publication now includes the required gate module for
both cached-image and no-ACR paths. Only Maester changes in the package lock.

This is an assessment slice, not a complete Container host migration. The old
image/delivery design is retained and is not qualified for PowerShell 7.6; the
runner now fails closed on older engines. Reconcile the standalone reviewed
7.6.6 image/bootstrap and keyless bundle stack before deployment. Do not deploy
this slice over the retained scheduled environment. Its deployed source is
unknown and its Azure Files/Shared Key configuration differs from standalone
#56. Setup consent, execution-bound receipts, runtime-only validation, native
image/identity access, report freshness/publication, lifecycle/cancellation and
owned cleanup remain open. Azure DevOps migration also remains open. No
identity, role, topology, schedule, network or Azure resource change is made.
