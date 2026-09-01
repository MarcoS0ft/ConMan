# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's
**Security** tab using **Report a vulnerability**. Do not open a public issue
for a suspected vulnerability and do not include credentials, private keys,
tokens, host inventories, or other sensitive data in public discussions.

Include the affected version or commit, operating system, impact, and the
smallest safe reproduction you can provide. Logs are useful after removing
credentials and environment-specific details.

We will acknowledge a report, investigate it, and coordinate disclosure and a
fix as appropriate. Please allow time for remediation before publishing the
details.

## Supported versions

ConMan is currently distributed as rolling development builds. Security fixes
land on the latest `master` revision and are included in the next successful
rolling release. Older development builds are not maintained separately.

## Credential and trust model

ConMan stores secrets in the operating system's credential service rather than
in its configuration file or SQLite database. SSH host-key and RDP certificate
verification are enabled by default. The documented automatic-trust settings
are intended only for controlled environments and are disabled by default.
