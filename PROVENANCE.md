# Prior work and consolidation

NoBrainer Security is the single public home for this focused repository-review workflow. It is a new repository, not a renamed copy of an older project.

The earlier `nobrainer-fast-audit` skill in the public NoBrainer skills history covered whole-machine diagnostics, installed skills, incident indicators, and platform hardening. Its narrow pre-installation skill-vetting idea informs this repository's entry-point and trust-boundary questions. This workflow does **not** copy its broad machine scan or its unverified threat statistics.

The earlier `nobrainer-npm-secure` skill covered dependency cooldowns, lifecycle scripts, and lockfiles. Its useful concept is a release-age control. Security now assesses a 14-day window as the standard recommendation in dependency-relevant reviews. The current [policy](dependency-age-policy.md) requires manager and version detection, change scope, security-fix tradeoff, and rollback before any configuration change. Historical version claims and commands must be checked against current vendor documentation.

Both legacy skill paths were inspected in the `nobrainer-claude-skills` local checkout and its Git history on 2026-09-26. That checkout and the former public skills names resolve to the current [NoBrainer Tech Flow](https://github.com/nobrainer-tech/nobrainer-tech-flow) project. The reviewed public Flow main ref was `f39b0444d29febe00403a870d334b6292fe4a118` on that date. On 2026-09-30 the workflow moved to Flow v2.0.2 (`bec696ff199bd1ad79524d7d3e2bffce3d28e796`), whose technical entrypoint is `$nobrainer-tech-flow`; the earlier `$nobrainer-ultra` name no longer exists. The changes since v2.0.0 concern installation and small skill text fixes, not the `nobrainer-security` specialist. Security remains a focused workflow over Flow, not a second agent engine. No legacy repository or its history has been imported here.

`nobrainer-tech/claude-code-security-review` is a fork of Anthropic's project, not a predecessor authored for this workflow. It has a different role: a GitHub Action reviewing code changes. No code from it is incorporated here. Its existing repository and visibility are left unchanged.

## Review lenses and their licenses

The review lenses in [WORKFLOW.md](WORKFLOW.md#review-lenses) summarize public guidance in our own words and link to it; no code or long text is copied. Sources checked on 2026-09-30:

- OWASP [Secure Code Review Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html), [ASVS](https://owasp.org/www-project-application-security-verification-standard/), and [Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- OpenAI [security-best-practices](https://github.com/openai/skills/tree/main/skills/.curated/security-best-practices) and [security-threat-model](https://github.com/openai/skills/tree/main/skills/.curated/security-threat-model) skills, each with its own license file (Apache 2.0 for security-best-practices when checked). Their rule that project documents may override a practice is deliberately not adopted, because a reviewed target's documents are untrusted.
- Anthropic [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) (MIT). Its false-positive filtering informs how candidates are rejected. Its README limits the action to trusted pull requests because it is not hardened against prompt injection, so this workflow keeps its own untrusted-input boundary.

The package inspector and report renderer in [tools/](tools/) were written for this repository and use only the Python standard library.

