# Security website

Source for `https://nobrainer.tech/security/`. The landing page and the example report are standalone files with no build step.

Publish only these files into the `/security/` directory:

- `index.html`
- `xray-gift-wide.webp`, `xray-gift-wide.jpg` (social preview image)
- `xray-gift-crop.webp`, `xray-gift-crop.jpg`
- `report-preview.webp`, `report-preview.jpg`
- `security-report-example.html`
- `security-report-example.md`

The example report is the approved controlled example. [`tools/render_report.py`](../tools/render_report.py) renders the same design from review data; `tests/fixtures/controlled-report.json` reproduces this example. Its HTML view switches to Markdown for download, copy, and a scoped fix request for NoBrainer.Tech Flow. Creating the request runs nothing.

The Start NoBrainer Tech Security Audit dialog pins a workflow commit. Update that commit when a new workflow release should become the default.

Do not synchronize a whole website or remove unrelated server files. Record the destination preimage, verify an isolated dry run, upload assets before the index, and read back the public files by hash. Rollback restores the exact preimage; for new files it removes only the introduced files after verifying their hashes.
