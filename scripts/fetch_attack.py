"""Explicit optional download of a pinned official catalog; ingestion remains offline."""

from pathlib import Path
import hashlib
import json
import sys
from urllib.request import urlopen


def main():
    root = Path(__file__).resolve().parents[1]
    metadata = json.loads((root / "configs/attack_catalog.json").read_text())
    target = root / "data/attack_catalog/enterprise-attack-17.1.json"
    if target.exists():
        if (
            target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != metadata["sha256"]
        ):
            raise ValueError(
                "Existing catalog differs from the pinned digest; preserve it and investigate."
            )
        print("Pinned ATT&CK 17.1 catalog already verified.")
        return
    # URL is pinned in reviewed config, never taken from an intelligence record.
    if (
        metadata["url"]
        != "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v17.1/enterprise-attack/enterprise-attack.json"
    ):
        raise ValueError("Unexpected catalog origin")
    with urlopen(metadata["url"], timeout=60) as response:  # noqa: S310 -- fixed HTTPS origin
        body = response.read(64 * 1024 * 1024 + 1)
    if len(body) > 64 * 1024 * 1024 or hashlib.sha256(body).hexdigest() != metadata["sha256"]:
        raise ValueError("Catalog checksum verification failed; no artifact retained")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as output:
            output.write(body)
    except FileExistsError:
        # Another explicit setup process may have retained the same pinned artifact.
        if (
            target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != metadata["sha256"]
        ):
            raise ValueError("Concurrent catalog write failed verification") from None
    print("Official ATT&CK 17.1 catalog downloaded and checksum verified.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print("Catalog retrieval or verification failed.", file=sys.stderr)
        raise SystemExit(1) from None
