# Automation runtime package lock

`infra/main.bicep` imports exact PSGallery package versions into the PowerShell
7.4 Automation runtime. Each `contentLink` records the SHA-256 of the downloaded
`.nupkg`. The lab accepted a deliberately incorrect `contentHash` during an
Automation package import, so that ARM field is **not an enforced integrity
boundary**. The published local runbook independently downloads each exact
package version, checks its bytes against the reviewed SHA-256, and imports it
from an isolated path. A missing or changed core package fails before the
managed identity connects to Graph; an enabled optional package is verified
before its service connection and before Maester runs. These hashes establish
byte integrity, not publisher authentication.

Versions were observed in the succeeded `PowerShell-74-Maester` runtime package
resources in the selected lab on 2026-10-03. Package hashes were then computed
from `https://www.powershellgallery.com/api/v2/package/<name>/<version>` on the
same date. No Maester or Graph runbook execution was performed for this lock.

| Package | Exact version | SHA-256 of `.nupkg` |
| --- | --- | --- |
| Az.Accounts | 5.5.3 | `5A8BE006E80A7CA66134DF1F28E0EAD93EF4BC437685B647B6720583CB58E615` |
| Maester | 2.2.0 | `8C8A9757771177BD89785262E6B38385CF5E5C19BB799E4399E77F6439AD699C` |
| Pester | 6.2.0 | `E6AC7418D4F12500269AACA58AE56CF1CAAFBBF1AFA2CEC334E289D1CF50A239` |
| NuGet | 1.3.3 | `FCF1A37925C235159AB1C23249F016E65456EA3A36D0EA42DB85F4F15BF7C033` |
| PackageManagement | 1.4.8.1 | `7E1F8A75B6BC8A83D8ABFF79F6690FC1DFBD534FD3E5733D97E19BCB5954C13E` |
| PowerShellGet | 2.2.5 | `6B8CEBF2A464EAEB31B0A6D627355C30D9D1899DBA0CE3BDD0D4E7AFCA148673` |
| Microsoft.Graph.Authentication | 2.41.0 | `42E8B7A8BBA6AFD1910510D8108C1871EE5D12C5A4818CC4C36CA406369A7AFD` |
| ExchangeOnlineManagement | 3.10.1 | `545FB0FDF65B96ABED37F4F5B5D7DB661276DDC7DE48A742BB6E7199AB9414A3` |
| MicrosoftTeams | 8.0.0 | `6AA426D37913DEE78628AD36DFC26E40161702018479F110F396712E896F2882` |

The Exchange and Teams package resources are conditional on their respective
feature flags. A future update requires confirming compatibility, downloading
the new exact package bytes, updating the URI and hash together, and validating
the resulting runtime before promotion.

Infrastructure seeds the Automation runbook from Maester commit
`c657a4b8a24267ccd795edb0c7db402e0d440e3b` with SHA-256
`FF70CB4AB2F32ADA6C5FF5121931D3C8BE45BDBCDB746970C26FB275FFAD312F`.
This seed is not attached to the weekly schedule. Postprovision publishes the
local runbook, confirms its published content, and only then creates the weekly
job-schedule association. If setup or publication fails, no recurring run is
attached.
