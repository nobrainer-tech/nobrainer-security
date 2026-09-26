# Standard 14-day dependency-age policy

**Standard recommendation; assessment is mandatory in every dependency-relevant review. READ_ONLY: this repository does not apply package-manager settings.** A release-age window can reduce exposure to newly published compromised or defective versions. It can also delay an urgent security fix, and it does not prove that an older version is safe. Fourteen days is the default recommendation. Seven days is acceptable only as an explicit, documented project choice with its rationale; do not infer it from an existing machine setting.

## Evidence status

Record one status for each relevant package-manager/configuration scope in every review, alongside the manager and exact version, configuration source and precedence, scope (project, user, global, CI, registry, or other), relevant install commands/environments, and supporting evidence. Omit authentication values. The status describes evidence for this control only; it is not a general safety score.

- `NOT_APPLICABLE` — reviewed dependency manifests/lockfiles and scope show no relevant package dependencies.
- `NEEDS_SETUP` — dependencies are in scope, the manager/version supports an applicable age control, and the selected control is absent or weaker than required (14 days by default, or 7 days under an explicit documented project choice); also use this when a 7-day setting has no such choice. This is a finding about configuration evidence, not an instruction to change it.
- `CONFIGURATION_OBSERVED` — an identified configuration source contains an applicable window of at least 14 days, or a 7-day window matching an explicit documented project choice, but enforcement has not been behavior-tested across the reported scope. A weaker or unapproved window remains `NEEDS_SETUP`; a configuration file alone does not settle unknown precedence.
- `ENFORCEMENT_VERIFIED` — an authorized controlled behavior test on the exact manager/version and relevant configuration/registry scope proves that a version younger than the selected window is rejected and an eligible version is accepted. State what was not covered.
- `UNSUPPORTED` — the identified manager/version or dependency source does not support the applicable control, supported by version-specific official documentation. Explain the affected scope.
- `NOT_ASSESSED` — dependency relevance, manager/version, configuration precedence, or other evidence is insufficient to choose a more specific status; state what is missing.

Do not use `CONFIGURATION_OBSERVED` as proof of enforcement. Do not describe any status as an overall safety rating. If no dependencies are found, retain the evidence for `NOT_APPLICABLE`; if dependency evidence was not inspected, use `NOT_ASSESSED`.

## Assess the actual project

Identify every relevant package manager and exact version from the repository's trusted configuration and execution path. Read project and higher-priority configuration without printing authentication values. Record effective precedence and scope for local development and CI, including overrides and exclusions. Confirm feature support in version-specific official documentation before drawing conclusions. Do not change host or target settings as part of assessment.

For npm CLI v11.10.0 or later, a project `.npmrc` can contain:

```ini
min-release-age=14
```

The npm value is in days. npm documents that the resolver errors when no version qualifies; a cooldown can also prevent `npm audit fix` from selecting a newly published fix. The feature was added in npm CLI v11.10.0; earlier versions do not support this key.

For pnpm v11 or later, `pnpm-workspace.yaml` can contain:

```yaml
minimumReleaseAge: 20160
minimumReleaseAgeStrict: true
minimumReleaseAgeIgnoreMissingTime: false
```

The pnpm value is in minutes. pnpm introduced `minimumReleaseAge` in v10.16.0 and the strict and missing-time controls in v11.0.0. With `minimumReleaseAgeStrict: true`, resolution fails when no eligible version exists. With `minimumReleaseAgeIgnoreMissingTime: false`, resolution fails when registry metadata has no publication time; this can break installs against registries or mirrors that omit timestamps. Older pnpm versions do not support these controls, so do not claim equivalent fail-closed behavior without version-specific evidence.

Official documentation checked 2026-09-26:

- npm v11 configuration: https://docs.npmjs.com/cli/v11/using-npm/config/#min-release-age
- npm v11 changelog (feature added in v11.10.0): https://docs.npmjs.com/cli/v11/using-npm/changelog/
- pnpm v10 settings: https://pnpm.io/10.x/settings#minimumreleaseage
- pnpm dependency resolution settings (current documentation): https://pnpm.io/settings/dependency-resolution#minimumreleaseage

## Limits, exception, and verification

Review precedence, exclusions, registries, publication-time metadata, Git/file/tarball dependencies, lockfiles, and the install commands that CI actually runs. A configured value alone does not prove enforcement across all sources or environments. If registry metadata omits publication times, the pnpm option above makes resolution fail; confirm that behavior against the exact package-manager version and registry in use.

An age window may block a legitimate urgent security fix. A narrowly scoped exception may cover only the named package and exact fix version (or the smallest documented version range needed), with the security reason, approving owner, start and expiry/review time, and rollback step recorded. Do not lower the general window, add a broad or permanent exclusion, or silently upgrade a manager. Restore the recorded project baseline (14 days by default, or the explicitly approved 7-day choice) when the exception expires or the fix becomes eligible under it; verify and record the rollback. This workflow only documents and assesses the exception unless separate authority explicitly permits a change.

Prove behavior only in a separately authorized isolated project using controlled packages: a version inside the window should be rejected and an eligible older version accepted. Confirm the actual package-manager version, effective config, lockfile effect, and lifecycle-script behavior. Until that proof is run, report `CONFIGURATION_OBSERVED` (or `NEEDS_SETUP` when absent), not `ENFORCEMENT_VERIFIED`. Older releases are not necessarily safe; review advisories, provenance, integrity, and other relevant evidence separately. A cooldown may delay a security fix, and Git/file/tarball sources, registries, missing publication times, or unsupported manager versions can limit coverage.

`ignore-scripts` is a separate control with its own compatibility consequences. It does not make an explicitly invoked project script safe. Do not add it automatically as part of this age policy.
