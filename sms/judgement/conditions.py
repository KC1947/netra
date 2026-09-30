"""Evaluate YAML rule conditions with the reference closed grammar."""

from __future__ import annotations

import operator
import re


OPS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}
PATTERN = re.compile(
    r"^(?P<path>[a-z_][a-z0-9_.]*)\s*"
    r"(?P<op>==|!=|>=|<=|>|<|is not null|is null|is not empty|is empty)"
    r"\s*(?P<lit>\"[^\"]*\"|\'[^\']*\'|[^\s]*)\s*$",
    re.I,
)


class ConditionError(ValueError):
    pass


def _resolve(path: str, facts: dict):
    value = facts
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _literal(raw: str):
    value = raw.strip().strip('"').strip("'")
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "none"):
        return None
    try:
        return int(value, 16) if lowered.startswith("0x") else int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def evaluate(condition: str, facts: dict) -> bool:
    match = PATTERN.match(condition.strip())
    if not match:
        raise ConditionError(f"unsupported condition: {condition!r}")
    path, operation, literal = (
        match.group("path"), match.group("op").lower(), match.group("lit")
    )
    value = _resolve(path, facts)
    if operation == "is null":
        return value is None
    if operation == "is not null":
        return value is not None
    if operation == "is empty":
        return value is None or len(value) == 0
    if operation == "is not empty":
        return value is not None and len(value) > 0
    if not literal.strip():
        raise ConditionError(f"operator {operation!r} needs a value: {condition!r}")
    if value is None:
        return False
    try:
        return bool(OPS[operation](value, _literal(literal)))
    except TypeError:
        return False
