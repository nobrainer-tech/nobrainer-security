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

For each candidate rejected, record its location, benign explanation or effective guard, and evidence for rejection. Omit scanner noise that was not investigated.

## Dependency policy (when applicable)

- Package manager and exact version evidence:
- Configuration source and effective precedence, with auth values omitted:
- Requested release age and units:
- Exceptions, overrides, non-registry sources, and missing publication-time metadata:
- Lifecycle-script policy and lockfile scope:
- Controlled behavior test: run / not run, with result:
- Security-fix delay or other tradeoff:
- Change and rollback authority, if a change was separately approved:

## Evidence and limits

- Files and static traces inspected:
- Commands or tests actually run and their outputs:
- Current primary sources/advisories, versions, and dates:
- Unknowns, unreviewed areas, and blocked checks:
- Sensitive data omitted:
- Recommended next action and required authority:
