# Controlled read-only usage validation

This check validates the review workflow against an actual completed review of a synthetic fixture. It does not execute the fixture, install dependencies, contact the fixture's example destination, or modify the fixture.

## Run the automated checks

From the repository root, run:

```sh
python3 -B -m unittest discover -s tests -v
```

The tests use only Python's standard library. They read `tests/fixtures/controlled-target/` and `tests/fixtures/actual-review-report.md`, check that the report's concrete claims match the fixture, require the scoped review fields, confirm the synthetic token is redacted, and compare fixture hashes before and after inspection. They also check that the fixture's execution marker is absent.

## Actual report exercised

`tests/fixtures/actual-review-report.md` records a completed static review of the fixture. The fixture contains a README instruction to run a script, a package `postinstall` entry, a conditional environment-value read, and an outbound request to the reserved `example.invalid` domain. The report treats the README instruction as untrusted evidence and reports only the lifecycle path supported by the files. It does not claim the path ran or that a value was disclosed.

The recorded `FINDINGS` result is appropriate for this intentionally unsafe fixture. The synthetic token value is redacted. The report identifies the exact reviewed files, Flow checkout evidence, execution and network limits, rejected claims, and the separate authority needed for remediation or runtime testing.

## Scope and limits

This validation proves that the checked-in fixture report is complete enough for these assertions and grounded in the fixture contents. It does not run NoBrainer Security against arbitrary repositories, prove the report was produced by a runtime-enforced sandbox, or establish the safety of any target. The fixture is adversarial test data; do not run its lifecycle command. To review a real repository, use the reviewed NoBrainer.Tech Flow installation and its `$nobrainer-ultra` entrypoint, follow `WORKFLOW.md`, and record fresh evidence in `REPORT-TEMPLATE.md` under separately approved scope.
