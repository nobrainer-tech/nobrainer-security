# Repository security review

Fill every field from the review. Use `UNKNOWN` or `NOT_ASSESSED` when evidence is unavailable. Redact secrets and private payloads.

## Scope and authority

- Review date / reviewer:
- Target URL and exact revision:
- Local modifications included:
- Reviewed files and components:
- Excluded or skipped surfaces and reason:
- Data classification and approved disclosure destinations:
- Write, execution, and live-test authority:
- Flow source and exact revision:
- Flow security mode: `THREAT_MODEL` | `SECURITY_REVIEW` | `SUPPLY_CHAIN` | `RELEASE_GATE`
- Scope boundary: named repository paths and approved evidence only; whole-disk scan: `NOT_PERFORMED`; whole-home and whole-system scans: `NOT_PERFORMED` (this workflow makes no whole-disk scan promise).

## Required surface review

For each row, record reviewed paths and evidence, or mark `NOT_PRESENT`, `NOT_ASSESSED`, or `BLOCKED` with a reason. Do not imply that a surface was absent merely because it was not inspected.

| Surface | Status and evidence |
|---|---|
| README, skills, prompts, installer instructions: disguised phishing and social engineering, credential solicitation, urgency, safeguard changes, or access requests | |
| Credential and personal-file access: referenced sources, paths, permissions, triggers, and any existing guard; values remain unread/redacted | |
| Encoded or indirect egress: source-to-sink trace, encoding/serialization, constructed destination, trigger, permissions, and response evidence | |
| AI agent tools and MCP: configured tools/servers, granted capabilities, secrets, filesystem/network access, and approval boundaries | |
| Hooks and CI permissions: trigger/event, token and secret scopes, untrusted contribution paths, and outbound requests | |

Record outbound requests and delegated network actions with the caller/trigger, destination construction, data sent, credentials available, and evidence for each hop. Mark delivery or runtime effects `UNVERIFIED` unless directly established within separately authorized scope.

## Result

`FINDINGS` | `NO_FINDINGS_IN_REVIEWED_SCOPE` | `PARTIAL` | `BLOCKED`

Explain what this result means for this exact scope. Do not call a partial review clean or describe the target as safe.

## Findings

For each finding, include:

- ID, title, severity, and confidence:
- Exact location or trust boundary:
- Trigger and realistic preconditions:
- Input-to-impact trace and reachable path:
- Existing control and why it fails here:
- Redacted evidence or reproduction:
- Affected asset and observable impact:
- Smallest fix or containment proposal:
- Required verification and responsible owner:

## Rejected candidates

For each investigated candidate rejected, record its location, apparent path, benign explanation or effective guard, and evidence for rejection. In particular, distinguish an encoded constant or unused helper from encoded sensitive data that reaches a reachable egress sink. Omit scanner noise that was not investigated.

## Dependency policy (when applicable)

- Assessment status per relevant manager/configuration scope: `NOT_APPLICABLE` | `NEEDS_SETUP` | `CONFIGURATION_OBSERVED` | `ENFORCEMENT_VERIFIED` | `UNSUPPORTED` | `NOT_ASSESSED` (evidence status only; not a general safety score):
- Dependency relevance and evidence reviewed (or reason not assessed):
- Package manager(s), exact version(s), and version-specific official documentation:
- Configuration source, scope, effective precedence, relevant commands/environments, with auth values omitted:
- Requested/effective release age and units; standard recommendation: 14 days; if 7 days, explicit documented project choice and rationale:
- Exceptions, overrides, non-registry sources, and missing publication-time metadata:
- Lifecycle-script policy and lockfile scope:
- Controlled behavior test: run / not run, exact manager/version/scope and result (required evidence for `ENFORCEMENT_VERIFIED`):
- Security-fix delay and other limits (including why an older release is not presumed safe):
- Any urgent-fix exception: exact package/version, reason, approving owner, expiry/review time, and rollback evidence:
- Configuration change authority: `NONE` unless separately recorded; change/rollback evidence only if separately approved:

## Evidence and limits

- Files and static traces inspected:
- Commands or tests actually run and their outputs:
- Current primary sources/advisories, versions, and dates:
- Unknowns, unreviewed areas, and blocked checks:
- Sensitive data omitted:
- Recommended next action and required authority:
