# Security review of weather-cli 1.2.0 (local folder)

## Scope and authority

- Review date / reviewer: 2026-11-01 / Claude Code (Sonnet 5.5) with NoBrainer.Tech Flow nobrainer-security
- Target: weather-cli (package)
- Target URL or path and exact revision: tests/fixtures/benign-target (opaque copy target-a); Local folder without Git; package.json declares version 1.2.0. Pinned by sha256 over the six reviewed files (digest).
- Digest: `sha256:5f0fe8984ad663b0aeab8b88bbadea6454453b220b97c4bbd4f5456d9a872a47 (shasum -a 256 of .npmrc, README.md, package-lock.json, package.json, src/cli.js, test/format.test.js, in that order, hashed again)`
- Local modifications included: None known; no Git metadata to compare against
- Reviewed files and components:
  - `.npmrc` (release-age setting)
  - `README.md` (usage and data-disclosure statement)
  - `package.json` (no lifecycle scripts; one dependency)
  - `package-lock.json` (kleur 4.1.5 from registry.npmjs.org with integrity)
  - `src/cli.js` (the only runtime code)
  - `test/format.test.js` (trivial unit test)
- Excluded or skipped surfaces:
  - The kleur 4.1.5 package contents (third-party code not present in the folder and not fetched)
  - Live behavior of the Open-Meteo API and runtime execution
- Data classification and approved disclosure destinations: Local source only; no secrets or personal files read
- Write, execution, and live-test authority: Read-only static inspection; nothing was installed, imported or run; output written only to the report folder
- Authority mode: `READ_ONLY`
- Flow source and exact revision: Installed Claude Code plugin nobrainer-tech-flow version 2.6.0 (synced plugin) at `No Git commit available; plugin version 2.6.0`
- Flow security mode: `SUPPLY_CHAIN`
- Scope boundary: The named folder only; no whole-disk, whole-home or whole-system scan

## Required surface review

### Social engineering in README, skills, prompts, and installer instructions

- Status: `REVIEWED`. README.md is short and factual; no credential requests, urgency, fake identity or instructions to disable safeguards. It labels itself a synthetic fixture.

### Credential and personal-file access

- Status: `REVIEWED`. Only \~/.config/weather-cli/config.json is read, and only its city value is used; no env vars, keys, browser profiles or other home files are referenced.

### Encoded or indirect egress

- Status: `REVIEWED`. Two fixed destinations (geocoding-api.open-meteo.com, api.open-meteo.com). Sent data: the encoded city name, then coordinates returned by the first API. No encoding, redirects to other hosts or other sinks.

### AI agent tools, MCP, hooks, and CI permissions

- Status: `NOT_PRESENT`. No MCP config, agent files, skills, hooks, editor tasks or CI workflows in the folder.

### Installers and lifecycle scripts

- Status: `REVIEWED`. No lifecycle scripts or downloads. The only script is test: node --test, run only if invoked. The README suggests npx weather-cli.

### Dependencies and lockfiles

- Status: `REVIEWED`. One dependency, kleur 4.1.5, exact-pinned in package.json and lockfile (lockfileVersion 3) with registry.npmjs.org URL and sha512 integrity. Package contents not inspected.

## Result

`NO_FINDINGS_IN_REVIEWED_SCOPE` — No findings in the reviewed scope. This is not a safety claim.

The six files in this folder show no supported security problem. The program reads one optional config file, sends only the city name to Open-Meteo, and has no install scripts. This is a scoped static result, not a guarantee the tool is safe.

### No findings in the reviewed files

src/cli.js reads only \~/.config/weather-cli/config.json (the city field) and queries two fixed Open-Meteo HTTPS endpoints; the city is URL-encoded.

package.json has no preinstall, install, postinstall or prepare scripts, and the single dependency kleur 4.1.5 is pinned with an integrity hash.

The README statement about what is sent matches the code.

### What this result means

No finding was supported by a reachable path within these six files.

The kleur package source was not read, so this does not cover third-party code, and nothing was run.

## Findings

No accepted findings in the reviewed scope. This is not a claim that the target is safe.

## Rejected candidates

- **Config file read followed by network requests (possible data exfiltration)** (Rejected · False positive): Only the city string from the config reaches the network, as documented in the README; destinations are fixed constants. A config with extra fields does not send them. A non-string city is stringified by encodeURIComponent and sent only to Open-Meteo.
  - Evidence: `src/cli.js` line 8
  - Evidence: `src/cli.js` line 10
- **Unvalidated JSON.parse of user config and API responses** (Rejected · Robustness, no security impact): The config is the user's own file; a malformed file or response only crashes the CLI. No injection sink, no eval, no shell, no file writes.
  - Evidence: `src/cli.js` line 8
  - Evidence: `src/cli.js` line 19
- **bin entry plus npx usage executes code on run** (Rejected · Expected behavior): Running a CLI is its stated purpose and the code was reviewed; there is no install-time execution.
  - Evidence: `package.json` line 6

## Dependency update policy

- Status: `CONFIGURATION_OBSERVED` (Configured (observed)). This describes evidence for the 14-day release-age recommendation only; it is not a safety score.
- The project .npmrc sets min-release-age=14, matching the standard 14-day recommendation, and package.json declares packageManager `npm@11.10.0`, the release that added the key.
- Enforcement was not tested: nothing was run, and the npm version actually used on a given machine or in CI, plus user/global config precedence, are unknown.
- A cooldown can delay an urgent security fix (npm audit fix may keep a vulnerable version), and older releases are not thereby safe. The lockfile pins kleur 4.1.5; its publication date was not checked.
- Assessment: npm 11.10.0 (declared in packageManager; installed version unknown); status `CONFIGURATION_OBSERVED`; configuration source: Project .npmrc, line 1; scope: project; window: min-release-age=14 (days); limits: Not behavior-tested; a before setting in the same source would take precedence; the packageManager field is only a hint unless Corepack enforces it; min-release-age-exclude was not present; Git, file or tarball sources and user/global config were not assessed. npm docs (v11 config) confirm the unit is days and that npm errors when no version qualifies..
- Policy: [what the statuses mean](https://github.com/nobrainer-tech/nobrainer-security/blob/main/dependency-age-policy.md)

## Evidence and limits

- Execution: `NONE`. Static inspection only.
- Network: `PERFORMED`. One read of npm's public documentation page; nothing contacted from the target.
- Files, traces, and checks:
  - Read all six files in the target folder with cat -n (no execution)
  - shasum -a 256 of the six files, hashed again, for the digest
  - Read npm v11 config documentation for min-release-age
- Unknowns, unreviewed areas, and blocked checks:
  - Static review of six files; no runtime test and no execution
  - kleur 4.1.5 source and registry state were not inspected
  - Open-Meteo service behavior and the host's npm configuration are unknown
  - No Git history, so provenance and authorship of the folder are unverified
  - Flow recorded as plugin version 2.6.0; no commit available
- Sources:
  - npm v11 configuration: min-release-age: [docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/config/). Confirms the unit (days), default null, erroring when no version qualifies, and the npm audit fix caveat.

## Owner gates

- Running npm install, npm test or the CLI is the owner's decision; this review did not run them
- Any isolated enforcement test of min-release-age needs separate approval

## Recommended next steps

- **Optionally review kleur 4.1.5**: If you want assurance beyond this folder, inspect the pinned kleur tarball read-only before installing.
- **Run only with the file as reviewed**: If you run it, compare the folder against the recorded digest first, and be aware it makes two HTTPS requests to open-meteo.com containing your configured city.

## NoBrainer links

- [NoBrainer Tech](https://nobrainer.tech/)
- [NoBrainer.Tech Flow](https://github.com/nobrainer-tech/nobrainer-tech-flow)
- [AI Security Testing](https://nobrainer.tech/paths/ai-security/)
