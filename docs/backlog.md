# Backlog: nathanmcnulty/azd-maester

> Generated from `docs/backlog.json`. Edit the JSON source and regenerate this file.
> Standard: [azd agent backlog standard](https://github.com/nathanmcnulty/azd-reference/blob/main/standards/agent-backlogs.md). This link is review guidance, not a runtime dependency.

- **Schema version:** 1.0.0
- **Repository:** nathanmcnulty/azd-maester
- **Source revision:** `9c86e879f43de090f6fbee0fbb5f35ecbc83c374`
- **Captured:** 2026-10-07
- **Items:** 8

## MCAT-001: Reconcile this backlog with current source and active work

- **Kind:** discovery
- **Priority:** P1
- **Status:** done
- **Wave:** 0
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Plans and implementation evidence are spread across files; the captured source can change while other tasks work.

**Scope:**

- docs/backlog.json
- docs/backlog.md
- Existing roadmap, execution status, open issues and pull requests &lpar;read-only&rpar;

**Acceptance:**

- Classify each candidate as implemented, still open, superseded or awaiting evidence; retain source links and reasons.
- Inspect dirty state, remotes, worktrees and local environment presence without reading secrets; avoid duplicate work with active owners.
- Resolve the actual offline validation commands and record exact current default-branch/working-tree provenance; do not copy historical live passes to newer code.

**Validation:**

- git status --short
- git remote -v
- git worktree list --porcelain
- Read the applicable instructions and validation workflow; read gh issue list and gh pr list for the named repository using nathanmcnulty. Do not create or modify issues/PRs.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- README.md
- https&colon;//github.com/nathanmcnulty/azd-maester/pull/26
- https&colon;//github.com/nathanmcnulty/azd-maester/pull/28
- https&colon;//github.com/nathanmcnulty/azd-maester/pull/30

**Evidence:**

- Reconciled against current main 4b6328701541126e677abc9400a35092d4cd6f66 in a clean worktree. Issues &num;24, &num;25 and &num;27 are resolved by merged PR &num;28 after the partial PR &num;26 runner fix; issue &num;29 is resolved by merged PR &num;30. Issues &num;2, &num;4, &num;5, &num;8 and &num;12 through &num;15 remain open and map to the proposed feature/migration items. Existing GUI, runtime-pin and README worktrees were inventoried and preserved; no .azure or .env path was present.
- Issue &num;27 source resolution is PR &num;28&colon; Resolve-DeploymentTarget.psm1 in all four variants, setup/pre/post scripts and DeploymentTargetBinding.Tests.ps1 bind mutations and receipts to authoritative azd environment/deployment outputs. Issue &num;29 source resolution is PR &num;30 at current main&colon; automation-account/README.md now names Invoke-RunbookValidation.ps1 with required target parameters; documentation validation did not run an Azure job.
- Current-base combined offline Pester validation passed 124/124 across root, Automation, Container App Job, Function App and Azure DevOps suites. Provider-looking test messages were produced by mocks; no Azure, Graph, schedule, report delivery or endpoint operation ran.

**Review and authorization note:**

Review MCAT-001 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-007: Pin legacy runtime dependencies and define ownership of diverged nested sources

- **Kind:** discovery
- **Priority:** P1
- **Status:** done
- **Wave:** 0
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open report captured 2026-10-03 during execution reconciliation. Another code-quality task may own an active fix; inspect its PR and current source before dispatch.

**Scope:**

- Linked issue and current source &lpar;read-only&rpar;
- Repository-local backlog evidence

**Acceptance:**

- Read the linked issue and current default branch; classify the exact defect, current owner and evidence gap.
- Record a current PR or verified resolution before selecting any implementation; preserve broader feature and live acceptance gates.

**Validation:**

- Read current issue and PR state using nathanmcnulty; do not modify or close issues during reconciliation.
- Inspect dirty state and worktrees; resolve the exact current revision and relevant offline commands before implementation.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-maester/issues/25
- https&colon;//github.com/nathanmcnulty/azd-maester/pull/28

**Evidence:**

- Issue &num;25 is fixed by merged PR &num;28 at d7e65b34b8e37ab7d73b156919f1ae77984602c6&colon; each legacy variant carries immutable runtime package locks, installers and explicit runtime-contract provenance while remaining independently deployable. The PR reports independent byte review, the full offline Pester suite, four Bicep builds, parser and provenance checks; no grants, deliveries, schedules or endpoint changes occurred.

**Review and authorization note:**

Review MCAT-007 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-008: Legacy nested runners and validators can report success after execution failures

- **Kind:** discovery
- **Priority:** P1
- **Status:** done
- **Wave:** 0
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open report captured 2026-10-03 during execution reconciliation. Another code-quality task may own an active fix; inspect its PR and current source before dispatch.

**Scope:**

- Linked issue and current source &lpar;read-only&rpar;
- Repository-local backlog evidence

**Acceptance:**

- Read the linked issue and current default branch; classify the exact defect, current owner and evidence gap.
- Record a current PR or verified resolution before selecting any implementation; preserve broader feature and live acceptance gates.

**Validation:**

- Read current issue and PR state using nathanmcnulty; do not modify or close issues during reconciliation.
- Inspect dirty state and worktrees; resolve the exact current revision and relevant offline commands before implementation.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-maester/issues/24
- https&colon;//github.com/nathanmcnulty/azd-maester/pull/26
- https&colon;//github.com/nathanmcnulty/azd-maester/pull/28

**Evidence:**

- Issue &num;24 is fixed in current main by PR &num;26 and completed by merged PR &num;28&colon; Automation, Container, Function and Azure DevOps runners now fail on invocation, missing reports and publication errors; validation triggers and receipts are correlated and packaging fails closed. PR &num;28 reports the full offline Pester suite and four Bicep builds. No hosted run or report delivery is claimed.

**Review and authorization note:**

Review MCAT-008 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-002: Make standalone migration and remaining catalog support explicit

- **Kind:** maintenance
- **Priority:** P1
- **Status:** done
- **Wave:** 1
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

The root is a guard/catalog and the four standalone hosts are the long-term source; backlog work must not duplicate host fixes.

**Scope:**

- README.md
- docs/
- azure.yaml

**Acceptance:**

- Map each legacy folder to its canonical standalone host and move future work to that host backlog.
- Root remains non-deployable and folder commands remain accurate during migration.
- Archive or remove folders only after separate authorization and verified history/evidence; no implicit cleanup.

**Validation:**

- Use the offline commands in the registered validation workflow; record the exact commands, revision and results before implementation is complete.
- Run focused tests for changed behavior from tests/; fixtures do not prove live-service or endpoint behavior.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- README.md
- azure.yaml
- scripts/Run-AzdRootGuard.ps1
- https&colon;//github.com/nathanmcnulty/azd-maester-azureautomation/blob/main/docs/backlog.json
- https&colon;//github.com/nathanmcnulty/azd-maester-containerappjob/blob/main/docs/backlog.json
- https&colon;//github.com/nathanmcnulty/azd-maester-functionapp/blob/main/docs/backlog.json
- https&colon;//github.com/nathanmcnulty/azd-maester-azuredevops/blob/main/docs/backlog.json
- https&colon;//github.com/nathanmcnulty/azd-maester-azuredevops/pull/18
- https&colon;//github.com/nathanmcnulty/azd-maester/issues/12
- https&colon;//github.com/nathanmcnulty/azd-maester/issues/13
- https&colon;//github.com/nathanmcnulty/azd-maester/issues/14
- https&colon;//github.com/nathanmcnulty/azd-maester/issues/15

**Evidence:**

- At exact base 9c86e879f43de090f6fbee0fbb5f35ecbc83c374, README.md maps each retained legacy folder to its canonical standalone repository, host backlog, standalone azd init source and accurate legacy folder command. Read-only GitHub metadata confirmed all four hosts are unarchived with main as the default branch, each README names the documented azd init source, and each docs/backlog.json exists.
- The repository root remains non-deployable&colon; azure.yaml routes preup and preprovision through scripts/Run-AzdRootGuard.ps1, and a focused offline invocation rejected the root while printing all four retained folder commands. No folder was removed or archived.
- Issues &num;12 through &num;15 remain open. Standalone Azure DevOps PR &num;18 merged as 6d1930742b93b16dfaf61bc0ceb8f215f6eff5f4 and only repairs repository staging when TEMP is absent with focused cleanup tests; this documentation does not close those issues or claim a future Reference wizard correction or standalone consumer update.
- Registered offline validation passed 124/124 Pester tests, four Bicep builds and repository-wide PowerShell parsing. Focused mapping checks verified the four standalone links, default branches, README sources and host backlogs. Only README.md and canonical/generated backlog documentation changed; no runtime, deployment, authentication, cloud, publication or cleanup action occurred.

**Review and authorization note:**

Review MCAT-002 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-003: Feature&colon; Add support for custom Maester tests

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open GitHub report captured 2026-10-03. Reproduce against the current source and reconcile active PRs before changing code; the issue remains the detailed trigger/evidence reference.

**Scope:**

- Paths and trigger cited in the linked issue
- Focused offline regression tests
- docs/

**Acceptance:**

- Classify the report as still reproducible, already fixed, superseded or requiring live evidence; record the exact current revision.
- For a reproducible defect, demonstrate the linked trigger with an offline regression and apply the smallest fix preserving tenant/target/ownership and failure semantics.
- For a feature, produce a bounded design with compatibility, optional permissions, acceptance and rollout gates before implementation; no live mutation or automatic issue closure.

**Validation:**

- Read the issue body and current source/PRs; capture the exact reproduction and existing registered offline validation command.
- Use deterministic fixtures for the described trigger and negative boundary; retain current-source results. Do not rerun production or tenant operations to reproduce it.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-maester/issues/8
- README.md

**Evidence:**

- _none_

**Review and authorization note:**

Review MCAT-003 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-004: Feature&colon; Add -IncludeContainerWebApp option &lpar;Caddy&rpar; to all solutions

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open GitHub report captured 2026-10-03. Reproduce against the current source and reconcile active PRs before changing code; the issue remains the detailed trigger/evidence reference.

**Scope:**

- Paths and trigger cited in the linked issue
- Focused offline regression tests
- docs/

**Acceptance:**

- Classify the report as still reproducible, already fixed, superseded or requiring live evidence; record the exact current revision.
- For a reproducible defect, demonstrate the linked trigger with an offline regression and apply the smallest fix preserving tenant/target/ownership and failure semantics.
- For a feature, produce a bounded design with compatibility, optional permissions, acceptance and rollout gates before implementation; no live mutation or automatic issue closure.

**Validation:**

- Read the issue body and current source/PRs; capture the exact reproduction and existing registered offline validation command.
- Use deterministic fixtures for the described trigger and negative boundary; retain current-source results. Do not rerun production or tenant operations to reproduce it.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-maester/issues/5
- README.md

**Evidence:**

- _none_

**Review and authorization note:**

Review MCAT-004 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-005: Feature&colon; Add -IncludeStaticWebApp option to all solutions

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open GitHub report captured 2026-10-03. Reproduce against the current source and reconcile active PRs before changing code; the issue remains the detailed trigger/evidence reference.

**Scope:**

- Paths and trigger cited in the linked issue
- Focused offline regression tests
- docs/

**Acceptance:**

- Classify the report as still reproducible, already fixed, superseded or requiring live evidence; record the exact current revision.
- For a reproducible defect, demonstrate the linked trigger with an offline regression and apply the smallest fix preserving tenant/target/ownership and failure semantics.
- For a feature, produce a bounded design with compatibility, optional permissions, acceptance and rollout gates before implementation; no live mutation or automatic issue closure.

**Validation:**

- Read the issue body and current source/PRs; capture the exact reproduction and existing registered offline validation command.
- Use deterministic fixtures for the described trigger and negative boundary; retain current-source results. Do not rerun production or tenant operations to reproduce it.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-maester/issues/4
- README.md

**Evidence:**

- _none_

**Review and authorization note:**

Review MCAT-005 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## MCAT-006: Add support for drift analysis

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Open GitHub report captured 2026-10-03. Reproduce against the current source and reconcile active PRs before changing code; the issue remains the detailed trigger/evidence reference.

**Scope:**

- Paths and trigger cited in the linked issue
- Focused offline regression tests
- docs/

**Acceptance:**

- Classify the report as still reproducible, already fixed, superseded or requiring live evidence; record the exact current revision.
- For a reproducible defect, demonstrate the linked trigger with an offline regression and apply the smallest fix preserving tenant/target/ownership and failure semantics.
- For a feature, produce a bounded design with compatibility, optional permissions, acceptance and rollout gates before implementation; no live mutation or automatic issue closure.

**Validation:**

- Read the issue body and current source/PRs; capture the exact reproduction and existing registered offline validation command.
- Use deterministic fixtures for the described trigger and negative boundary; retain current-source results. Do not rerun production or tenant operations to reproduce it.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-maester/issues/2
- README.md

**Evidence:**

- _none_

**Review and authorization note:**

Review MCAT-006 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.
