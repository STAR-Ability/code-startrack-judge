# Security

Code Startrack Judge & Problem Service runs hostile code and handles private test data. Phase 0 establishes policies and development tooling; there is no production release or validated execution sandbox yet. No release is currently designated security-supported.

Report exploitable issues through [GitHub private vulnerability reporting](https://github.com/STAR-Ability/code-startrack-judge/security/advisories/new) which is enabled for this repository. If GitHub reporting is temporarily unavailable, contact a repository owner through an existing private channel to arrange disclosure. Do not put credentials, hidden tests, source code from another user, or working exploit instructions in a public Issue. No public security mailbox has been designated; maintainers must monitor the enabled private reporting route and set production response expectations before launch.

Include the affected commit/release, environment, impact, and a minimal reproduction using synthetic data. Maintainers should acknowledge privately, reproduce on an isolated host, agree on disclosure, prepare a reviewed fix and regression evidence, and identify affected releases. Published supported release ranges and response expectations belong here once production support exists.

For active incidents, stop accepting new execution, isolate the affected sandbox host, revoke affected tokens, preserve restricted evidence, and assess database/object integrity before recovery. Do not erase historical tasks to hide an incident.

The durable [security model](docs/security/model.md), [Linux validation requirements](docs/development/linux-sandbox.md), and [production deployment gates](docs/deployment/production.md) govern implementation and operation. Report policy improvements publicly using synthetic examples; report vulnerabilities privately.
