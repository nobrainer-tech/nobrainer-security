# Security website

Source for `https://nobrainer.tech/security/`. The landing page and controlled HTML report are standalone files; the report is an example, not an automatic report generator.

Publish only these files into the `/security/` directory:

- `index.html`
- `security-hidden-catch.png`
- `security-report-example.html`
- `security-report-example.md`

Do not synchronize a whole website or remove unrelated server files. Record the destination preimage, verify an isolated dry run, upload assets before the index, and read back the final public files. Rollback restores the exact preimage; for a first publication it removes only the introduced files after verifying their hashes.

The example report offers HTML/Markdown views, Markdown download, and a scoped fix-request builder for NoBrainer.Tech Flow. Creating a prompt does not execute it. The fixture example targets a disposable copy and excludes rejected candidates from the fix list.
