# Prior work and consolidation

NoBrainer Security is the single public home for this focused repository-review workflow. It is a new repository, not a renamed copy of an older project.

The earlier `nobrainer-fast-audit` skill in the public NoBrainer skills history covered whole-machine diagnostics, installed skills, incident indicators, and platform hardening. Its narrow pre-installation skill-vetting idea informs this repository's entry-point and trust-boundary questions. This workflow does **not** copy its broad machine scan or its unverified threat statistics.

The earlier `nobrainer-npm-secure` skill covered dependency cooldowns, lifecycle scripts, and lockfiles. Its useful concept is a release-age control. Security now assesses a 14-day window as the standard recommendation in dependency-relevant reviews. The current [policy](dependency-age-policy.md) requires manager and version detection, change scope, security-fix tradeoff, and rollback before any configuration change. Historical version claims and commands must be checked against current vendor documentation.

Both legacy skill paths were inspected in the `nobrainer-claude-skills` local checkout and its Git history on 2026-09-26. That checkout and the former public skills names resolve to the current [NoBrainer Tech Flow](https://github.com/nobrainer-tech/nobrainer-tech-flow) project. The reviewed public Flow main ref was `f39b0444d29febe00403a870d334b6292fe4a118`. Security remains a focused workflow over Flow, not a second agent engine. No legacy repository or its history has been imported here.

`nobrainer-tech/claude-code-security-review` is a fork of Anthropic's project, not a predecessor authored for this workflow. It has a different role: a GitHub Action reviewing code changes. No code from it is incorporated here. Its existing repository and visibility are left unchanged.
