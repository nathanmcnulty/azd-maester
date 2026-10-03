# Pipeline runtime package lock

`runtime-packages.lock.json` records exact PowerShell Gallery `.nupkg` versions
and SHA-256 hashes for every module the pipeline can import, including the
optional Exchange, Teams, and Web App modules. The AzureCLI task exposes the
existing workload-identity service connection token; the runner creates its
own Az PowerShell context from that token after verifying and importing the
locked modules. The task runs on the `windows-2022` hosted image. Azure DevOps
controls updates to that hosted image and built-in task implementation; those
platform components cannot be byte-pinned by this template.

The installer downloads each exact version, checks the package bytes before
extracting them, and prepends the isolated module directory to `PSModulePath`.
The setup hook copies both the installer and lock into the generated pipeline
repository alongside the runner. Updating a module requires a reviewed exact
version, a new package hash, and an import test before promotion.

For failed pipeline runs, validation accepts Maester findings only when the
runner is the sole failed task, both report publishers succeed, and the
`TestResults` artifact exists. The NUnit publisher does not fail its task on
test findings; the runner emits the specific finding marker after writing the
report and NUnit result. Missing or failed artifacts remain validation errors.
