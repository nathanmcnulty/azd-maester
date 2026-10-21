# Automation runtime package lock

`infra/main.bicep` imports exact PSGallery package versions into the PowerShell
7.6 Automation runtime. Each `contentLink` records the SHA-256 of the downloaded
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
same date. That historical inventory included Maester 2.2.0, not the newly adopted
2.3.0 package. No Maester or Graph runbook execution was performed for that historical lock.

The retained source now adopts reviewed Maester 2.3.0 package bytes from the
standalone migration. Its local offline compatibility evidence is separate from
those October 3 observations and does not establish current Azure execution.

| Package | Exact version | SHA-256 of `.nupkg` |
| --- | --- | --- |
| Az.Accounts | 5.5.3 | `5A8BE006E80A7CA66134DF1F28E0EAD93EF4BC437685B647B6720583CB58E615` |
| Maester | 2.3.0 | `95F720822D04271F5E15F4665BC017111DC72E17B97E5D0525CB4EC2FF5BD0B0` |
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
`7413c42d3fcc724dfea94d2726e690ddd364d914` with SHA-256
`87CEB74D50309360C592816BFC963A6D370B66C51AE71D45A01117651BF7F5A8`.
This seed is not attached to the weekly schedule. Postprovision publishes the
local runbook, confirms its published content, and only then creates the weekly
job-schedule association. If setup or publication fails, no recurring run is
attached.
