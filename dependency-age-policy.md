# Optional 14-day dependency-age policy

**Proposal only. This repository does not apply package-manager settings.** A release-age window can reduce exposure to newly published compromised or defective versions. It can also delay an urgent security fix, and it does not prove that an older version is safe.

## Check the actual project first

Identify the package manager and exact version from the repository's trusted configuration and execution path. Read project and higher-priority configuration without printing authentication values. Confirm the setting is supported by the version actually used in local development and CI before proposing it.

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
- pnpm dependency resolution: https://pnpm.io/settings/dependency-resolution#minimumreleaseage

## Limits and verification

Review precedence, exclusions, registries, publication-time metadata, Git/file/tarball dependencies, lockfiles, and the install commands that CI actually runs. A configured value alone does not prove enforcement across all sources or environments. If registry metadata omits publication times, the pnpm option above makes resolution fail; confirm that behavior against the exact package-manager version and registry in use.

An age window may block a legitimate urgent fix. Any exception should identify the affected package and version, the reason, the approving owner, and a review or expiry condition. Avoid broad or permanent exclusions. Do not silently upgrade a package manager or change global configuration to make this policy work.

Prove behavior only in a separately authorized isolated project using controlled packages: a version inside the window should be rejected and an eligible older version accepted. Confirm the actual package-manager version, effective config, lockfile effect, and lifecycle-script behavior. Until that proof is run, report the state as `PROPOSED` or `CONFIGURATION_OBSERVED`, not `ENFORCEMENT_VERIFIED`.

`ignore-scripts` is a separate control with its own compatibility consequences. It does not make an explicitly invoked project script safe. Do not add it automatically as part of this age policy.
