"""Canonicalization is identity, never attribution. No network operations."""

import hashlib
import ipaddress
import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

ENTITY_TYPES = {
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "file_hash",
    "file",
    "malware_sample",
    "malware_family",
    "process",
    "registry_key",
    "sandbox_report",
    "intelligence_report",
    "attack_technique",
    "attack_tactic",
    "campaign",
    "threat_actor",
    "source",
    "investigation",
}
SCOPED_TYPES = {"file", "process", "registry_key"}


def stable_id(prefix: str, *parts: object) -> str:
    body = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return prefix + "_" + hashlib.sha256(body.encode()).hexdigest()


def normalize(entity_type: str, value: str) -> str:
    if entity_type not in ENTITY_TYPES:
        raise ValueError("unsupported entity type")
    value = value.strip()
    if not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid entity value")
    if entity_type in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(value)
        if address.version != (4 if entity_type == "ipv4" else 6):
            raise ValueError("IP version mismatch")
        return str(address)
    if entity_type == "domain":
        result = value.rstrip(".").encode("idna").decode("ascii").lower()
        if len(result) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in result.split(".")
        ):
            raise ValueError("invalid domain")
        return result
    if entity_type == "url":
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("only absolute HTTP(S) URLs supported")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URL credentials are forbidden")
        if any(
            re.search(r"password|secret|token|api.?key|authorization|credential", key, re.I)
            for key, _ in parse_qsl(parts.query)
        ):
            raise ValueError("URL credential query parameters are forbidden")
        host = parts.hostname
        try:
            ip = ipaddress.ip_address(host)
            host = f"[{ip}]" if ip.version == 6 else str(ip)
        except ValueError:
            host = normalize("domain", host)
        port = parts.port
        scheme = parts.scheme.lower()
        if port is not None and port != (443 if scheme == "https" else 80):
            host += f":{port}"
        # Query and fragment are preserved: collapsing them can merge different resources.
        return urlunsplit((scheme, host, parts.path or "/", parts.query, parts.fragment))
    if entity_type == "file_hash":
        result = value.lower()
        if not re.fullmatch(r"[0-9a-f]+", result) or len(result) not in {32, 40, 64, 128}:
            raise ValueError("expected MD5, SHA1, SHA256 or SHA512 hex digest")
        return result
    if entity_type == "attack_technique":
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value.upper()):
            raise ValueError("invalid ATT&CK technique ID")
        return value.upper()
    if entity_type == "attack_tactic":
        if not re.fullmatch(r"TA\d{4}", value.upper()):
            raise ValueError("invalid ATT&CK tactic ID")
        return value.upper()
    # Named entities use source-scoped IDs, not human display names.
    return value
