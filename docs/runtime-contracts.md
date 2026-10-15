# Nested Maester runtime contracts

The four subdirectories remain independently deployable. Their runtime, package,
validation, and infrastructure files are locked in `runtime-contracts.lock.json`.
Each entry records the standalone repository and exact reviewed commit used as
its source, plus SHA-256 of both the standalone and nested files. Hashes use
UTF-8 text without a BOM and normalize line endings to LF so Windows and Linux
checkouts validate identically.

The lock distinguishes exact standalone copies from maintained variants and
records the reason for each difference. The maintained Automation and Function
entry points require PowerShell 7.6. Host-specific behavior includes selected
environment binding, owned-schedule validation, the Container Job's stable name,
and Azure DevOps authorization setup. Local helper and hook files are tracked
separately when absent from the pinned standalone revision.
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
