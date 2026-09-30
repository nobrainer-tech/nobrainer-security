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

## Controlled AI-review fixtures

Three small targets are supplied for the next independent usage check:

- [controlled-target](tests/fixtures/controlled-target/) contains deliberately unsafe setup behavior and harmless look-alikes.
- [recruiter-target](tests/fixtures/recruiter-target/) models a coding exercise with install-time behavior and instructions aimed at the reviewer.
- [benign-target](tests/fixtures/benign-target/) models a documented weather CLI and a project release-age setting.

Fixture code must not be installed or executed. Existing tests check selected static paths, redaction, policy evidence and unchanged files. The three-target blind review has not completed: configured worker providers returned HTTP 429 or HTTP 402 before producing reports. These fixtures and their tests are not proof that the full workflow detects risks on arbitrary inputs.

## Generated report

[controlled-report.json](tests/fixtures/controlled-report.json) is review data built from the previously approved controlled example. Generate its HTML report and matching Markdown outside the target:

```sh
python3 -B tools/render_report.py tests/fixtures/controlled-report.json --out-dir /tmp/nobrainer-security-report
```

Open `/tmp/nobrainer-security-report/report.html`. Its MD view offers Markdown copy/download and a Flow fix request built from accepted findings only. This is a renderer demonstration, not a new independent audit. Delete the output directory after reviewing it.

See [VALIDATION.md](VALIDATION.md) for the checks actually performed, pending usage evidence and limits.
