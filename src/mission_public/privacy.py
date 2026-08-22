"""Recursive pre-persistence privacy and credential-secret filtering."""

from __future__ import annotations

import json
import re
from typing import Any

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.I | re.S)),
    ("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.I)),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    # Security secrets are self-identifying: they must be redacted standalone,
    # not only when they follow a recognised key label.
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,255}|github_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9]{20,})\b")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("CREDENTIAL", re.compile(r"(?i)\b(api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|oauth[_ -]?code|authorization)\b\s*[:=]\s*['\"]?[^\s,'\";]{4,}")),
    ("EMAIL", re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)),
    ("SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    # Ordered most specific first: the digit-run classes below would otherwise
    # absorb an address and label it with the wrong class marker.
    ("PERSON_NAME", re.compile(
        r"(?i)(?<!\w)(?:full[ _-]?name|first[ _-]?name|last[ _-]?name|vorname|nachname|"
        r"ansprechpartner|kontaktperson|contact[ _-]?person|patient|customer|kunde|name)"
        r"[\"']?\s*[:=]\s*[\"']?(?-i:[A-Z][^\W\d_]*[.'’-]?(?:\s+[A-Z][^\W\d_]*[.'’-]?)+)")),
    ("POSTAL_ADDRESS", re.compile(
        r"(?i)(?<!\w)(?:"
        r"\d{1,5}[a-z]?\s+(?:[A-Za-zÀ-ɏ.'’-]+\s+){0,3}"
        r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl|terrace|parkway|highway|loop)\.?(?!\w)"
        r"|[A-Za-zÀ-ɏ.'’-]*(?:stra(?:ss|ß)e|str|weg|gasse|allee|platz|ring|damm|ufer)\.?\s+\d{1,4}[a-z]?(?!\w)"
        r"|(?:Unter\s+den|Am|An\s+der|Auf\s+der)\s+(?:[A-ZÀ-ɏ][A-Za-zÀ-ɏ.'’-]*\s+){0,3}[A-ZÀ-ɏ][A-Za-zÀ-ɏ.'’-]*\s+\d{1,4}[a-z]?(?!\w)"
        r"|\d{5}\s+[A-ZÀ-ɏ][A-Za-zÀ-ɏ.'’-]+(?:[ -][A-ZÀ-ɏ][A-Za-zÀ-ɏ.'’-]+)*"
        r")")),
    # Match mixed IPv6/IPv4 forms as one unit before the standalone IPv4 rule
    # can redact only the dotted tail and leave network topology behind.
    ("IPV6_ADDRESS", re.compile(
        r"(?<![:.\w])(?:"
        r"(?:[0-9A-Fa-f]{1,4}:){1,6}"
        r"|(?:[0-9A-Fa-f]{1,4}:){0,5}:"
        r")(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![:.\w])")),
    ("IPV6_ADDRESS", re.compile(
        r"(?<![:.\w])(?:"
        r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
        r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
        r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
        r"|::(?:[Ff]{4}(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r")(?![:.\w])")),
    ("IP_ADDRESS", re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")),
    ("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")),
    ("PHONE", re.compile(r"(?<!\w)(?:\+?\d[\d .()/-]{7,}\d)(?!\w)")),
)
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|secret|token|credential|api[_-]?key|authorization|oauth|private[_-]?key|session[_-]?id)"
)
_WHOLE_PERSON_NAME = re.compile(
    r"^[A-Z][^\W\d_]*(?:[.'’-][A-Z]?[^\W\d_]*)?"
    r"(?:\s+[A-Z][^\W\d_]*(?:[.'’-][A-Z]?[^\W\d_]*)?)+$"
)


def redact_text(value: str) -> str:
    """Redact common PII and credential material using stable class markers."""
    output = value
    for label, pattern in _PATTERNS:
        output = pattern.sub(f"[REDACTED:{label}]", output)
    return output


def redact_person_name_field(value: str) -> str:
    """Apply generic scanning plus a narrow whole-field person-name rule."""
    output = redact_text(value)
    if output == value and _WHOLE_PERSON_NAME.fullmatch(value.strip()):
        return "[REDACTED:PERSON_NAME]"
    return output


def redact(value: Any) -> Any:
    """Recursively redact string leaves and values under secret-bearing keys."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        output: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _SENSITIVE_KEY.search(key):
                output[key] = "[REDACTED:CREDENTIAL]"
            else:
                output[key] = redact(item)
        return output
    return value


def redact_json_text(value: str | None, default: Any) -> str:
    parsed = default if value in (None, "") else json.loads(value)
    return json.dumps(redact(parsed), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
