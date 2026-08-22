"""Finite RFC 8785/JCS canonical JSON used by signatures and raw request identity."""
from __future__ import annotations

from decimal import Decimal
import json
import math
from typing import Any

_MAX_EXACT_INT = 2**53 - 1


class CanonicalizationError(ValueError):
    pass


def _number(value: int | float) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CanonicalizationError("not a number")
    if isinstance(value, int):
        if abs(value) > _MAX_EXACT_INT:
            raise CanonicalizationError("integer outside IEEE-754 exact domain")
        return str(value)
    if not math.isfinite(value):
        raise CanonicalizationError("non-finite number")
    if value == 0:
        return "0"
    negative = value < 0
    decimal = Decimal(repr(-value if negative else value))
    if Decimal("1e-6") <= decimal < Decimal("1e21"):
        output = format(decimal, "f")
        if "." in output:
            output = output.rstrip("0").rstrip(".")
    else:
        mantissa, exponent = format(decimal.normalize(), "e").split("e")
        mantissa = mantissa.rstrip("0").rstrip(".")
        exponent_number = int(exponent)
        output = f"{mantissa}e{'+' if exponent_number >= 0 else ''}{exponent_number}"
    return "-" + output if negative else output


def canonicalize(value: Any) -> bytes:
    def render(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, (int, float)):
            return _number(item)
        if isinstance(item, str):
            try:
                item.encode("utf-8", "strict")
            except UnicodeError as exc:
                raise CanonicalizationError("invalid Unicode") from exc
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(render(element) for element in item) + "]"
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
            return "{" + ",".join(render(key) + ":" + render(item[key]) for key in keys) + "}"
        raise CanonicalizationError("outside JSON domain")

    return render(value).encode("utf-8")
