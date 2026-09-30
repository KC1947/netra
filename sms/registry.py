"""Cryptographic knowledge loaded lazily from the offline registry."""

from __future__ import annotations

import functools
import os
from pathlib import Path

import yaml


# Importing this module never reads the filesystem. Resolution is anchored to
# the repository so callers are independent of their current working directory.
DEFAULT_PATH = os.environ.get(
    "NETRA_REGISTRY",
    str(Path(__file__).resolve().parent.parent / "rules" / "algorithms.yaml"),
)


def _hexkeys(values):
    return {
        (int(key, 16) if isinstance(key, str) else key): value
        for key, value in (values or {}).items()
    }


class Registry:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        registry_path = Path(path or DEFAULT_PATH)
        with registry_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        self.version = data["registry_version"]
        self.groups = _hexkeys(data.get("groups"))
        self.ciphers = _hexkeys(data.get("ciphers"))
        self.version_ordinals = _hexkeys(data.get("versions"))
        self.version_names = _hexkeys(data.get("version_names"))
        self.protocol_versions = _hexkeys(data.get("protocol_versions"))
        self.cipher_codes_by_name = {
            entry["name"]: code for code, entry in self.ciphers.items()
        }

    def classify_group(self, group):
        if group is None:
            return "NOT_OBSERVABLE"
        entry = self.groups.get(group)
        return entry["class"] if entry else "UNKNOWN"

    def group_name(self, group):
        entry = self.groups.get(group)
        return entry["name"] if entry else (None if group is None else f"UNKNOWN_0x{group:04X}")

    def group_cbom(self, group):
        """Return registry-owned CycloneDX fields for a named group."""
        entry = self.groups.get(group)
        if entry is None or "cbom" not in entry:
            return None
        return {"name": entry["name"], **entry["cbom"]}

    def is_pq_hybrid(self, group):
        return self.classify_group(group) == "PQ_HYBRID"

    def cipher_has(self, cipher, prop):
        entry = self.ciphers.get(cipher)
        return None if entry is None else prop in entry.get("props", [])

    def cipher_name(self, cipher):
        entry = self.ciphers.get(cipher)
        return entry["name"] if entry else (None if cipher is None else f"UNKNOWN_0x{cipher:04X}")

    def cipher_algorithms(self, cipher):
        """Return registry-owned algorithm composition for a cipher suite."""
        entry = self.ciphers.get(cipher)
        if entry is None:
            return ()
        return tuple(dict(algorithm) for algorithm in entry.get("cbom_algorithms", ()))

    def known_cipher(self, cipher):
        return cipher in self.ciphers

    def cipher_has_by_name(self, name, prop):
        """Tri-state property lookup for callers holding only the suite name.

        Returns ``None`` for a suite the registry cannot identify, so an
        unregistered code point stays *unknown* instead of being read as a
        negative. Deciding this from substrings of ``UNKNOWN_0xNNNN`` reported
        "not CBC, not AEAD" about a suite the engine had already admitted it
        could not name.
        """
        if name is None:
            return None
        code = self.cipher_codes_by_name.get(name)
        return None if code is None else self.cipher_has(code, prop)

    def version_ord(self, version):
        return self.version_ordinals.get(version)

    def version_name(self, version):
        return self.version_names.get(version, None if version is None else f"0x{version:04X}")

    def protocol_version(self, version):
        return self.protocol_versions.get(
            version, None if version is None else f"0x{version:04X}"
        )

    def downgrade_delta(self, offered_versions, negotiated):
        """Return offered-minus-negotiated ordinals, or None for unknowns."""
        offered = [self.version_ord(version) for version in (offered_versions or [])]
        offered = [ordinal for ordinal in offered if ordinal is not None]
        selected = self.version_ord(negotiated)
        if not offered or selected is None:
            return None
        return max(0, max(offered) - selected)


@functools.lru_cache(maxsize=4)
def load(path: str | None = None) -> Registry:
    """Load and cache a registry only when a caller first needs it."""
    return Registry(path)
