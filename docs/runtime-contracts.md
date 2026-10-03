# Nested Maester runtime contracts

The four subdirectories remain independently deployable. Their runtime, package,
validation, and infrastructure files are locked in `runtime-contracts.lock.json`.
Each entry records the standalone repository and exact reviewed commit used as
its source, plus SHA-256 of both the standalone and nested files. Hashes use
UTF-8 text without a BOM and normalize line endings to LF so Windows and Linux
checkouts validate identically.

Twenty-three files match the reviewed standalone source exactly. Twelve files
retain documented legacy behavior or add exact deployment target binding:
Automation's signed evidence validation, the Container Job's stable name,
legacy Azure DevOps authorization setup, and the Function App's hosting and
setup shape. Four copied local target-binding modules, three preprovision hooks,
and three legacy postprovision readers are tracked separately because they are
not present in the pinned standalone revisions. Automation's owned-schedule
helper matches standalone commit `201caff54f515d30e5d6d87aa882d722112cd58f`
exactly; its preprovision and setup scripts adapt that revision to the nested
selected-environment contract.
Setup first verifies that the current azd selection matches the requested
target. It takes storage, workload, managed identity, and optional Web App
identities from that environment's Bicep outputs, verifies the named resources
and workload principal before the first role or Graph write, and binds receipts
to the same environment. Postprovision summaries use those exact outputs too,
including the deployed optional Web App flag.
Each preprovision hook verifies the selected default environment before its
pinned wizard can write. Automation persists its schedule receipt to that
environment explicitly. Automation also preserves existing schedules and locks,
using complete ownership receipts or explicit adoption for a preexisting
account. Graph lookup collections must be complete before an application can
be created. Their reasons and hashes are in the lock.
`tests/RuntimeContracts.Tests.ps1` fails if a nested file changes without an
explicit lock update. A lock update is a review step, not a package download;
each nested solution carries its own package lock or Automation runbook
verification and never fetches code from a sibling repository at deployment.
The repository workflow runs nested tests and compiles all four Bicep templates
with Bicep 0.46.1 before publishing a change.
