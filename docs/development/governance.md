# Repository governance

`main` is the stable release branch and repository default. `dev` is the active integration branch. The empty remote was initialized with a **content-free** baseline commit `3ea253a`; all Phase 0 files are committed only to `dev`. This is a one-time branch bootstrap, not a release or normal direct delivery to `main`.

The active [main release protection ruleset](https://github.com/STAR-Ability/code-startrack-judge/rules/24657826) targets only `refs/heads/main`, requires a PR and resolved review conversations, and blocks force pushes and branch deletion. Zero mandatory approvals permits the current small team to operate without locking out its sole maintainer. Repository administrators have explicit emergency bypass. Normal administrator work follows the PR path too; bypass use must record the incident, reason, resulting commit and follow-up review in an Issue. At least one reviewer should independently examine security-sensitive and release changes even while GitHub does not enforce approval count.

Release PRs `dev → main` use **merge commits**. Squashing this long-lived integration branch would lose its shared ancestry and complicate subsequent releases. Repository squash merging remains available for future feature PRs; the main ruleset permits only merge commits. Automatic branch deletion is disabled to protect `dev`. Do not introduce linear-history requirements that contradict this flow.

The real GitHub checks **`Portable foundation`** and **`PostgreSQL contracts`** (GitHub Actions app ID `15368`) are required on `main`. Both names and their app identity were read from actual check runs; both passed for clean V0.2 commit `cea1dc1a2679a0b31b1c90675bf86e2862adb0ea` in [Foundation run 37701702769](https://github.com/STAR-Ability/code-startrack-judge/actions/runs/37701702769). PostgreSQL enforcement protects the implemented persistence, migrations, recovery and operator grants; portable checks alone can skip database fixtures without an explicit admin DSN. Strict up-to-date enforcement is disabled for the small-team flow; release PR validation and exact merged-commit validation still apply. No restrictions are applied to `dev` beyond team validation expectations. As the team grows, add `feature/* → PR → dev` and consider actual review/CI requirements after their check names and reliability are observed.

## CI and GitHub configuration

Foundation CI runs portable repository checks and actual PostgreSQL contract, recovery and operator-grant checks. Required check contexts must come from GitHub's real check runs, never guessed workflow/job strings. Record current enforcement changes and real observed context IDs/names in the relevant Issue and release evidence; preserve the [Phase 0 validation record](../releases/phase-0-validation.md) as the historical initial setup. Image publication and trusted Linux qualification remain separate workflows and release gates; no dummy success jobs.

Private vulnerability reporting and secret scanning/push protection are enabled for this public repository; [SECURITY.md](../../SECURITY.md) describes private reports. Treat scanner coverage as supplemental: it does not establish that all secrets are absent.

Reusable label groups are `type:*`, `area:*`, and `priority:P0/P1/P2`. Existing generic GitHub labels remain for discoverability; avoid duplicating their use for new scoped work. Priority indicates sequencing/impact, not authorization to bypass security.

Before changing governance, inspect real state:

```sh
gh repo view STAR-Ability/code-startrack-judge
gh api repos/STAR-Ability/code-startrack-judge/rulesets/24657826
gh api repos/STAR-Ability/code-startrack-judge/branches
gh workflow list --repo STAR-Ability/code-startrack-judge --all
gh run list --repo STAR-Ability/code-startrack-judge --branch dev
gh pr list --repo STAR-Ability/code-startrack-judge --state all
gh issue list --repo STAR-Ability/code-startrack-judge --milestone 'V0.2 Judge & Problem Service'
```

Do not replace existing organization rules blindly or enforce nonexistent checks. Keep `main` as default even while onboarding links point to `dev` during the unreleased foundation stage. Phase 0 creates no final release PR, tag, image, or deployment.
