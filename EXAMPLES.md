# Examples and observed results

The files below are outputs from actual package-inspection runs on 30 September 2026, not handwritten expected results. They demonstrate the inspector's static inventory and byte-verification step. The separate AI review turns that evidence into findings and a report; these inventories do not measure its detection quality.

## Memory-only package inspection

| Exact target | What the run observed | Output |
| --- | --- | --- |
| `esbuild@0.24.0` | 7 entries; registry SHA-512 and SHA-1 matched; the `postinstall` script was surfaced | [npm-esbuild.json](examples/package-inspection/npm-esbuild.json) |
| `six==1.16.0` | 19 entries in the source archive; registry SHA-256 matched; `setup.py` was surfaced as a build hook | [pypi-six.json](examples/package-inspection/pypi-six.json) |
| `nobrainer-tech/nobrainer-tech-flow@bec696ff199bd1ad79524d7d3e2bffce3d28e796` | 276 entries; the archive commit header matched; agent/instruction files and one binary were flagged; no upstream archive digest is published | [github-flow.json](examples/package-inspection/github-flow.json) |

All three runs completed without executing, installing or extracting artifact code. A Python audit hook registered before the inspector recorded zero write-type filesystem events. The shell saved JSON outside the inspector process. [audit-observations.json](examples/package-inspection/audit-observations.json) records the exact tool revision, tool/output hashes, observed DNS hosts and the limits of that measurement; it is not an operating-system sandbox proof.

The first two releases were older than 14 days. The GitHub commit was younger than 14 days, based on its committer date. This is a weak recency signal: a commit date is author-controlled and is not a publication timestamp. Neither age nor a matching digest establishes safety. Registry digests establish consistency with the registry's metadata, not trust in its publisher.

Repeat the inspected targets from the repository root:

```sh
python3 -B tools/inspect_package.py esbuild@0.24.0
python3 -B tools/inspect_package.py six==1.16.0
python3 -B tools/inspect_package.py nobrainer-tech/nobrainer-tech-flow@bec696ff199bd1ad79524d7d3e2bffce3d28e796
```

The fetch time, derived age and some remote metadata may differ on a later run. Read a flagged file with `--show PATH`; the contents remain untrusted data. Do not run the install hooks that an inventory identifies.

## Blind AI reviews of the controlled fixtures

On 1 November 2026 three fresh reviewers each audited one fixture with this workflow at `8599cf9`. They saw only the workflow files and an opaque, read-only copy of their target, not the tests, the other targets or the expected results. The reports below are their actual output.

| Fixture | What it models | Result | Report |
| --- | --- | --- | --- |
| [benign-target](tests/fixtures/benign-target/) | A documented weather CLI with a 14-day release-age setting | `NO_FINDINGS_IN_REVIEWED_SCOPE`; three look-alikes traced and rejected; release age `CONFIGURATION_OBSERVED` | [HTML](examples/blind-review/benign-target/report.html) · [MD](examples/blind-review/benign-target/report.md) |
| [controlled-target](tests/fixtures/controlled-target/) | Unsafe setup behavior next to harmless look-alikes | `FINDINGS`: High install hook that base64-encodes a token and a home file and POSTs them; High README lure; Low marker write. The harmless base64 label was rejected and the token value appears nowhere in the report | [HTML](examples/blind-review/controlled-target/report.html) · [MD](examples/blind-review/controlled-target/report.md) |
| [recruiter-target](tests/fixtures/recruiter-target/) | A take-home coding exercise with an install hook and a note aimed at AI assistants | `FINDINGS`: Critical `preinstall` upload of `.env` files and a home wallet file; Medium README pressure and reviewer-directed instructions; release age `NEEDS_SETUP` | [HTML](examples/blind-review/recruiter-target/report.html) · [MD](examples/blind-review/recruiter-target/report.md) |

All three matched the expected verdict. One expected detail was missed: the recruiter reviewer did not report that the pinned `left-pad` 1.3.0 is an old, deprecated release; it recorded the dependency as not established. [run-summary.json](examples/blind-review/run-summary.json) records the expected and observed results, target hashes, a minor boundary slip and the reviewers' friction notes.

Fixture code must not be installed or executed. Three small synthetic targets do not prove that the workflow detects risks on arbitrary inputs.

## Generated report

[controlled-report.json](tests/fixtures/controlled-report.json) is review data built from the previously approved controlled example. Generate its HTML report and matching Markdown outside the target:

```sh
python3 -B tools/render_report.py tests/fixtures/controlled-report.json --out-dir /tmp/nobrainer-security-report
```

Open `/tmp/nobrainer-security-report/report.html`. Its MD view offers Markdown copy/download and a Flow fix request built from accepted findings only. This is a renderer demonstration, not a new independent audit. Delete the output directory after reviewing it.

See [VALIDATION.md](VALIDATION.md) for the checks actually performed and their limits.
