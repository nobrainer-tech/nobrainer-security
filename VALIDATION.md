# Controlled read-only usage validation

This check validates the review workflow against a static review report for a synthetic fixture. It does not execute or import fixture code, install dependencies, read the referenced home-relative file, contact the fixture's example destination, scan outside the fixture, or modify the fixture.

## Run the automated checks

From the repository root, run:

```sh
python3 -B -m unittest discover -s tests -v
```

The tests use only Python's standard library. They read fixture and documentation text and parse the synthetic script into an AST without importing or executing it. Assertions connect the installer trigger, environment/personal-file sources, base64 encoding, constructed destination, and request sink; they also check that the benign static base64 label reaches only local printing, confirm the synthetic token is redacted, compare fixture hashes before and after inspection, and check that the execution marker is absent.

The suite also exercises the package inspector and report renderer. Inspector tests cover archive traversal, links and special entries, download and archive limits, digest mismatches, exact-version requirements, redirects, secret masking, and memory-only inspection without file writes. Renderer tests cover input validation, escaping, redaction, deterministic HTML/Markdown, Content Security Policy, and a fix request containing only accepted findings.

On 30 September 2026, all 80 tests passed. Seven report presentation regressions were reproduced before correction: misplaced candidate evidence, an unclear confidence qualifier, an unexplained unknown package-manager version, URL punctuation inside Markdown code spans, literal inline markup in the fix panel, repeated authorization labels, and doubled sentence punctuation. The generated reports were also checked in the Codex sidebar browser at 1440 and 390 pixels: HTML/MD switching, fix-request generation, exact clipboard copying of Markdown and the fix request, no horizontal overflow, and no observed console errors. Download completion was not reverified in this browser check.

## Actual package-inspection runs

[EXAMPLES.md](EXAMPLES.md) links the JSON from three real runs of the exact npm, PyPI and GitHub inputs. A Python audit hook observed zero write-type filesystem events in each inspector process. The archived packages were read in memory; their code was not installed, executed or extracted. The published observation record names the tool revision, output hashes and DNS hosts, and explains that this is Python-event evidence rather than an OS sandbox guarantee.

The inspector's private-key preview regression also failed before correction: only the BEGIN header was replaced, leaving the body visible. Tests now cover complete PKCS/OpenSSH/PGP blocks, an unterminated block, and key text inside lifecycle-script evidence. All 83 tests passed on 30 September 2026. Pattern masking is still a best-effort safeguard; reviewers must avoid retrieving or supplying real secret values.

## Actual report exercised

`tests/fixtures/actual-review-report.md` records a static review of the fixture. The README contains a synthetic support/urgency lure that solicits a token and urges installation. A package `postinstall` entry reaches a script that can read a synthetic environment value and a home-relative personal-file path, base64-encode the combined content, construct a URL from string fragments, and pass the result to an outbound POST request at the reserved `example.invalid` domain. A separate static base64 label is decoded only for local printing and has no sensitive source or egress sink; the report rejects it as a false positive. The report does not claim the install path ran or that a value was disclosed.

The recorded `FINDINGS` result is appropriate for the intentionally unsafe synthetic fixture. The token value is redacted. The report identifies the exact reviewed files, Flow checkout evidence, execution and network limits, rejected candidate, and separate authority needed for remediation or runtime testing. It explicitly states that no whole-disk/home/system scan was performed or promised.

## Scope and limits

This validation proves only that the checked-in report matches selected fixture evidence and that the text-level review contract includes the requested surfaces and scope limits. It does not run NoBrainer Security against arbitrary repositories, prove runtime enforcement or review quality on other targets, or establish the safety of any target. The fixture is adversarial test data; do not run its lifecycle command. To review a real repository, use a reviewed NoBrainer.Tech Flow installation (v2.0.2 or later) and its `$nobrainer-tech-flow` entrypoint, follow `SKILL.md` and `WORKFLOW.md`, and render fresh evidence with `tools/render_report.py` under separately approved scope.

The three-target blind usage check remains pending. On 30 September 2026, the configured native worker providers returned rate-limit errors (HTTP 429) or insufficient-funds errors (HTTP 402) before those reviews produced reports. Automated fixture checks and successful rendering do not substitute for that usage evidence.
