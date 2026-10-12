# Local catalog artifacts

`enterprise-attack-17.1.json` is the pinned official MITRE Enterprise ATT&CK STIX bundle.
It is retained in the prepared environment and ignored by Git because it is about 43 MiB.
`configs/attack_catalog.json` records its exact versioned origin and SHA256.
Run `python scripts/fetch_attack.py` explicitly to download/verify it on another machine.
Ordinary ingestion and tests never download anything.
