# Owner decision: Code Startrack project license

**Status: accepted, Apache-2.0, 2026-10-08.** The repository owner explicitly selected Apache-2.0 in the authorized complete V0.2 implementation task. Owner tracker: [#3](https://github.com/STAR-Ability/code-startrack-judge/issues/3). [LICENSE](../../LICENSE) contains the standard Apache License 2.0 text. [NOTICE](../../NOTICE) names Code Startrack contributors and retains the separately attributed upstream notices. Copyright years follow the year of the applicable contributions; this decision does not transfer ownership of third-party or contributor copyrights.

| Consideration | MIT | Apache-2.0 |
|---|---|---|
| Commercial use, modification and sale | Allowed | Allowed |
| Source or binary redistribution | Allowed with copyright and permission notice | Allowed with license copy, retained relevant notices and stated changes; applicable upstream NOTICE attribution must be carried |
| Disclosure of proprietary modifications | Not required | Not required |
| Attribution overhead | Short copyright and license text | Longer license, change notices and NOTICE handling when applicable |
| Patent terms | No explicit patent license in the text | Explicit contributor patent grant limited by the license, with patent-litigation termination |
| Warranty/liability | Disclaimers | Disclaimers; additional liability can only be accepted on the distributor's own behalf |
| Trademarks | No express trademark grant | Explicitly excludes trademark permission except normal origin/notice use |
| Four pinned upstreams | Their MIT notices must remain; Moby/Elastic Apache portions retain their own Apache terms | MIT portions retain their notices; Apache portions retain their terms and relevant NOTICE attribution |

Both are practical permissive choices for this infrastructure service. Apache-2.0 gives an explicit patent framework and more formal redistribution rules; MIT provides a shorter license and simpler attribution for owned code. Neither lets the project relabel third-party components or authorize imported problem content. Choosing MIT for owned code does not turn Apache-2.0 dependencies into MIT. Current reviewed MIT and Apache portions can coexist with either project choice when their obligations are separately honored; the incomplete transitive/bundled-content audit must still be resolved for a release.

Contributions to Code Startrack-owned source are accepted under Apache-2.0, as documented in [CONTRIBUTING.md](../../CONTRIBUTING.md). Third-party source and imported problem statements/tests/illustrations keep their own terms and evidence. The artifact-level license/NOTICE/SBOM audit remains a release gate; the owner selection alone does not prove compliance of an unbuilt image. Any future dependency with different terms gets a compatibility review at the actual version before adoption.
