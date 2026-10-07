# Repository governance

`main` is the stable release branch and repository default. `dev` is the active integration branch. The empty remote was initialized with a **content-free** baseline commit `3ea253a`; all Phase 0 files are committed only to `dev`. This is a one-time branch bootstrap, not a release or normal direct delivery to `main`.

The active [main release protection ruleset](https://github.com/STAR-Ability/code-startrack-judge/rules/24657826) targets only `refs/heads/main`, requires a PR and resolved review conversations, and blocks force pushes and branch deletion. Zero mandatory approvals permits the current small team to operate without locking out its sole maintainer. Repository administrators have explicit emergency bypass. Normal administrator work follows the PR path too; bypass use must record the incident, reason, resulting commit and follow-up review in an Issue. At least one reviewer should independently examine security-sensitive and release changes even while GitHub does not enforce approval count.

Release PRs `dev → main` use **merge commits**. Squashing this long-lived integration branch would lose its shared ancestry and complicate subsequent releases. Repository squash merging remains available for future feature PRs; the main ruleset permits only merge commits. Automatic branch deletion is disabled to protect `dev`. Do not introduce linear-history requirements that contradict this flow.

No restrictions are applied to `dev` beyond team validation expectations. As the team grows, add `feature/* → PR → dev` and consider actual review/CI requirements after their check names and reliability are observed.

## CI and GitHub configuration

Foundation CI starts with actual portable repository checks. Required check contexts must come from GitHub's real check runs, never guessed workflow/job strings. Record enforcement changes and real observed context IDs/names in the [Phase 0 validation record](../releases/phase-0-validation.md). Business test, image build, schema, license/SBOM and isolated Linux runtime jobs are added when implementation exists; no dummy success jobs.

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
