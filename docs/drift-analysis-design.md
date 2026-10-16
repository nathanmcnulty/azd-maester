# Optional configuration drift analysis

This is the MCAT-006 discovery/design result at catalog revision
`870cbe89dc00928935e145eb33e9799361221de0`, not an implemented host feature.
[Issue #2](https://github.com/nathanmcnulty/azd-maester/issues/2) is open and has
only a title. This design covers explicit JSON configuration baselines. Comparing
historical Maester pass/fail reports is a separate feature. MCAT-011 retains the
implementation and qualification work.

## Existing behavior and compatibility

The locked Maester 2.2.0 module exports `Compare-MtJsonObject` and accepts
`Invoke-Maester -DriftRoot`. Its bundled
`maester-tests/Maester/Drift/MT1060Drift.tests.ps1` discovers immediate child
folders, each with `baseline.json`, `current.json` and optional `settings.json`.
Four checks cover input validity, missing baseline properties and changed values.
Reuse this upstream comparison and rendering rather than adding another engine.

The [command reference](https://maester.dev/docs/commands/Invoke-Maester/)
confirms the parameter, but documentation can describe newer releases. This
assessment used the actual 2.2.0 package: `Maester.psm1` SHA-256
`53E80F21006FCEFFFA79F4D2F84D470BBADA9207114AAAB5EA85EDC8CC8BDA1E`.
Seven synthetic calls confirmed equal values, changed values, missing properties,
ignored extra current properties, array ordering, excluded names and ignored
scalar roots. They did not execute the upstream Pester suite, `Invoke-Maester`,
a collector or a report publisher. Separately, an empty current object produced
a comparison error during the attempted missing-property case.

Important limits:

- Only baseline properties are traversed; extra current properties are ignored.
  This is selected-property monitoring, not complete tenant configuration parity.
- Arrays are positional. Producers must define stable ordering for unordered
  collections; arbitrary sorting can change ordered policy semantics.
- Scalar roots can produce no differences. Require nonempty JSON object roots,
  explicit data schemas and a missing-property negative before enabling a case.
  Empty/malformed inputs or any comparison error must fail the run's drift gate.
- Exclusions match property names, including nested occurrences. Review the exact
  list with the baseline; exclusions must not grow automatically.
- Details contain paths and expected/actual values. Existing identity redaction
  does not establish redaction for arbitrary configuration values.
- `DriftRoot` sets process-level `MAESTER_FOLDER_DRIFT`. Omitted or invalid roots
  do not reliably clear a previous value. Clear it for disabled runs, and set and
  restore it with `try/finally` for enabled runs, including exceptions.

Fresh canonical default-branch runner inspection found no explicit `DriftRoot`
parameter or `MAESTER_FOLDER_DRIFT` handling at these revisions:

| Host | Revision | Integration point |
| --- | --- | --- |
| [Automation](https://github.com/nathanmcnulty/azd-maester-azureautomation/tree/47a1a62eedfb1d147216d7fcf1e0cd1365b66383) | `47a1a62eedfb1d147216d7fcf1e0cd1365b66383` | `scripts/Invoke-MaesterAutomationRunbook.ps1`, line 449 |
| [Container Apps Job](https://github.com/nathanmcnulty/azd-maester-containerappjob/tree/1f34605d23e4f0536c9215d21f6368d98f5c30f4) | `1f34605d23e4f0536c9215d21f6368d98f5c30f4` | `scripts/Invoke-MaesterContainerJob.ps1`, line 364 |
| [Function](https://github.com/nathanmcnulty/azd-maester-functionapp/tree/76976139f2026917484a91223ba278e9aa1fc058) | `76976139f2026917484a91223ba278e9aa1fc058` | `src/MaesterTimerTrigger/run.ps1`, line 430 |
| [Azure DevOps](https://github.com/nathanmcnulty/azd-maester-azuredevops/tree/80dd3bcab64cdbf5adafd7131f5ea47b378065f6) | `80dd3bcab64cdbf5adafd7131f5ea47b378065f6` | `scripts/Invoke-MaesterAzureDevOpsRun.ps1`, line 495 |

Recheck open runtime/authentication/viewer branches before integration. New code
belongs in canonical hosts; retained catalog folders receive no new feature.

## First implementation contract

Start with explicitly enabled, data-only local artifacts selected by an
administrator. Automatic baseline capture, tenant-wide collection, remediation,
background upload and baseline approval are outside this first implementation.
With drift disabled, preserve the existing assessment/report contract and prevent
discovery through ambient folders or an inherited drift environment variable.

Bind a manifest to schema version, nonzero tenant ID, environment/host, run ID,
immutable baseline revision and approval reference, current export producer and
revision, acquisition time, case IDs, schema/normalization revision, exclusions,
file lengths and SHA-256 hashes. Current input must match the selected run/target
and its declared freshness policy. Stale, foreign or unbound input cannot be
reported as current configuration. Digests prove bytes, not origin, collection
completeness or approval.

Initial limits: 32 cases, 1 MiB per JSON file, 16 MiB total, JSON depth 32. Require
unique bounded case IDs, fixed filenames, nonempty object roots and complete
manifest/file parity. Reject path traversal, links/reparse points, collisions,
unknown files, malformed/duplicate keys and changed bytes. Copy verified inputs
to an owned private run directory and execute only those bytes. Do not discover
scripts from the data artifact. Wire only the locked built-in drift suite and
selected data into the existing invocation/test-selection path.

Export producers own the allowlisted schema and normalization: omit secrets,
tokens, personal data and sensitive descriptions before creating inputs. The
first pilot uses synthetic non-sensitive configuration. Do not promise a general
redactor for arbitrary Graph responses. Review actual HTML/JSON/Markdown, logs
and job streams for output privacy, access and retention.

Keep baseline versions immutable. A separately reviewed administrator change
approves a new digest; drift, failed collection and missing files never update
the baseline. Rollback selects a previously approved digest or disables drift.
Cleanup removes only receipt-bound run artifacts and preserves approved baselines,
ordinary reports and another deployment's data.

## Permissions, components and acceptance

Local comparison requires no new Graph scope, Azure role, consent, credential or
service. Existing assessment permissions remain host-owned. A future collector
must name its exact API/resource and minimal permission delta. Neither this design
nor an artifact manifest authorizes collection or grants. Future storage transport
needs separate ownership, permission and lifecycle review.

Reuse the locked comparison and host report/failure contracts. A shared adapter
belongs in `azd-reference` after two real host integrations prove the boundary.
Release through the reference workflow, vendor reviewed immutable revisions and
hashes, and keep each host self-contained. This design adds no runtime fetch or
unused component lock.

MCAT-011 tracks implementation and must create canonical host tasks before their
runners change:

1. On PowerShell 7.6+/Pester 6.2, prove disabled behavior and actual locked suite
   discovery with equal, changed, missing and malformed inputs. An absent suite,
   zero discovered cases or comparison error cannot pass. Extra fields and order
   follow the documented selected-property model.
2. Cover manifest, tenant/run/source/freshness, changed bytes, JSON shape,
   duplicate keys, limits, paths/links, exclusions and inherited environment.
   No collector or unrelated test runs on invalid input. Verify restoration in a
   reused process, including failure paths.
3. Preserve report generation/publication failures and receipts. Add nonsecret
   hashes, target/run, expected/discovered case counts and separate comparison,
   report and publication outcomes. Inspect generated output for planted synthetic
   sensitive markers before any real-data pilot.
4. Independently review one adapter, then qualify the same contract in a second
   host before extracting a component. Native execution, report access, rollback
   and exact cleanup need separate evidence. Comparator calls prove none of those.
