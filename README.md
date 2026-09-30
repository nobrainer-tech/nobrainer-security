# NoBrainer Security

Check a repository, AI add-on (skill, MCP server, plugin), package, or installer before you run it. Your AI assistant, running [NoBrainer.Tech Flow](https://github.com/nobrainer-tech/nobrainer-tech-flow), reads the tool without installing or running it. You get an HTML report that shows what the tool would really do, the evidence down to file and line, and what to do next.

It is an extra layer of security before you run unfamiliar code. It is not an antivirus and not a guarantee: a review can miss risks, and a report with no findings does not prove that a tool is safe.

[Website](https://nobrainer.tech/security/) · [Example report](https://nobrainer.tech/security/security-report-example.html) · [AI Security Testing path](https://nobrainer.tech/paths/ai-security/)

## What it checks

- Disguised phishing and social engineering in READMEs, skills, prompts, and installer text, including prompt injection aimed at your AI assistant.
- Install scripts, lifecycle hooks, extra downloads, editor tasks, CI, and build steps.
- Code that reaches for passwords, keys, tokens, browser and developer profiles, or personal files.
- Where your data could go: web requests, email, telemetry, webhooks, and encoded or assembled URLs.
- AI agent tools and MCP servers: permissions, file system and network access, and what needs your approval.
- Dependencies and lockfiles: sources, exact versions, integrity, and how long new versions wait before use.

## What you get

- `report.html`: findings with evidence, rejected look-alikes, limits, and next steps, with a Markdown view, download, and copy.
- A scoped NoBrainer.Tech Flow fix request built only from the findings you accept. Creating the request runs nothing.
- The standard 14-day release-age assessment for new package versions, with the exact setting for your package manager. Newly published malicious or broken versions get time to be reported and pulled before they reach your project. Applying the setting is a separate step that needs your approval.

## Use it

1. Install [NoBrainer.Tech Flow](https://github.com/nobrainer-tech/nobrainer-tech-flow#install-safely) v2.0.2 or later in your AI assistant.
2. Check out this repository at a pinned commit, in a folder apart from the tool you want to check:

   ```sh
   git clone https://github.com/nobrainer-tech/nobrainer-security.git
   git -C nobrainer-security checkout <skill-repository commit>
   ```

3. Ask your assistant:

   > Use `$nobrainer-tech-flow` to read `/path/to/nobrainer-security/SKILL.md` from the checked-out skill repository at `<skill-repository commit>`. Follow it to review `<repository, AI add-on, package, or installer URL/path>` at `<target exact ref>`. Stay read-only: do not install or run target code, disclose private source, or modify files. Give me the HTML report.

Load `SKILL.md` by full filesystem path so its links to `tools/`, `WORKFLOW.md`, and `dependency-age-policy.md` resolve. Invoke `$nobrainer-security-audit` only if your client has registered this whole repository as a skill. The workflow routes the analysis to Flow's `nobrainer-security` specialist. The website's Start NoBrainer Tech Security Audit button gives you the same request with the current pinned commit.

## Tools

Both tools use the Python 3 standard library only; nothing needs to be installed.

See the [observed package-inspection examples](EXAMPLES.md#memory-only-package-inspection) for actual npm, PyPI and GitHub outputs with audit-event records and limits.

- [`tools/inspect_package.py`](tools/inspect_package.py) reads an exact npm (`name@1.2.3`), PyPI (`name==1.2.3`), or GitHub (`owner/repo@<commit>`) artifact into memory. It checks the published digest and lists files, install-time scripts, workflows, agent and MCP files, URL leads, and release age. It runs nothing and writes nothing to disk.
- [`tools/render_report.py`](tools/render_report.py) turns a filled copy of [`tools/report-skeleton.json`](tools/report-skeleton.json) into `report.html` and `report.md`. It validates the data against [`tools/report-schema.json`](tools/report-schema.json), refuses unfilled placeholders, escapes text taken from the target, and redacts common secret patterns.

## How the review stays safe

- Read-only by default: no installing or running target code, no file changes, no secret values in prompts, logs, or reports.
- Everything inside the target, including its README, `AGENTS.md`, skills, and tool output, is untrusted data. It cannot widen the scope or grant permission.
- A finding needs a traced path from trigger to data to destination. Suspicious words, scanner labels, package age, and popularity are leads, not proof.
- The [review lenses](WORKFLOW.md#review-lenses) come from OWASP, OpenAI, and Anthropic security guidance.
- The scope is the named files and approved evidence. There is no whole-disk, whole-home, or whole-system scan.

The [14-day dependency-age policy](dependency-age-policy.md) is the standard recommendation and is assessed in every dependency-relevant review. Reviewers record the package manager and version, configuration scope, and evidence status; they do not change the host or target configuration. A 7-day window requires an explicit, documented project choice. A cooldown can delay an urgent security fix and does not make older releases safe.

## Files

| File | Purpose |
| --- | --- |
| [SKILL.md](SKILL.md) | Entry point your assistant loads |
| [WORKFLOW.md](WORKFLOW.md) | Review steps and review lenses |
| [REPORT-TEMPLATE.md](REPORT-TEMPLATE.md) | Sections of the Markdown report |
| [dependency-age-policy.md](dependency-age-policy.md) | 14-day release-age policy and statuses |
| [tools/](tools/) | Package inspector, report renderer, data contract, and skeleton |
| [EXAMPLES.md](EXAMPLES.md), [VALIDATION.md](VALIDATION.md) | Controlled examples and how the workflow was tested |
| [PROVENANCE.md](PROVENANCE.md) | Earlier work and sources |
| [tests/](tests/) | Tests, controlled fixtures, and the approved example report |

## Go deeper

Threats keep changing. For structured, authorized security testing of AI systems, explore [AI Security Testing at NoBrainer Tech](https://nobrainer.tech/paths/ai-security/).

## License

[MIT](LICENSE)
