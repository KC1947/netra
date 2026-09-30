"""CycloneDX 1.6 CBOM export from observed server capabilities.

Algorithm knowledge comes entirely from the versioned offline registry, and
every support-matrix fact must pass the epistemic-tier gate before it can
contribute to the inventory.
"""

from __future__ import annotations

from collections.abc import Mapping
import uuid

from ..judgement.epistemic import Tier, require_tier
from ..registry import Registry, load as load_registry


_COMPONENT_TIERS = frozenset({Tier.OBSERVED, Tier.DEDUCED})


def _ref(kind: str, name: str) -> str:
    return f"crypto/{kind}/{name}".replace(" ", "-")


def _codepoint(key: str) -> int:
    return int(key.split(":", 1)[1], 16)


def _eligible_matrix_facts(matrix: Mapping[str, Mapping]) -> dict[str, Tier]:
    """Tier-check all matrix facts, returning demonstrated inventory facts."""
    eligible: dict[str, Tier] = {}
    for key in sorted(matrix):
        fact = matrix[key]
        tier = require_tier(dict(fact))
        if fact.get("state") == "DEMONSTRATED" and tier in _COMPONENT_TIERS:
            eligible[key] = tier
    return eligible


def build_cbom(
    report: Mapping,
    tool_version: str = "netra-1.5",
    *,
    registry: Registry | None = None,
) -> dict:
    """Build a deterministic CycloneDX 1.6 cryptography inventory.

    Excluded, inferred, undetermined and not-observable facts cannot produce
    components.  Missing or unknown tiers raise ``UntieredFactError`` through
    ``require_tier`` rather than becoming silently absent inventory entries.
    """
    registry = registry or load_registry()
    components: dict[str, dict] = {}

    def algorithm(
        name: str,
        primitive: str,
        mode: str | None = None,
        pq_level: int | None = None,
    ) -> str:
        # Primitive is part of the identity because RSA signature and RSA
        # public-key encryption are distinct CycloneDX algorithm assets.
        ref = _ref("algorithm", f"{name}-{primitive}")
        if ref not in components:
            properties = {
                "primitive": primitive,
                "executionEnvironment": "unknown",
                "cryptoFunctions": ["unknown"],
            }
            if mode is not None:
                properties["mode"] = mode
            if pq_level is not None:
                properties["nistQuantumSecurityLevel"] = pq_level
            components[ref] = {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": name,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": properties,
                },
            }
        return ref

    capture = report.get("capture", {})
    capture_sha256 = str(capture.get("sha256") or "unknown")

    for server in sorted(report.get("servers", ()), key=lambda item: item["server_id"]):
        matrix = server.get("support_matrix", {})
        eligible = _eligible_matrix_facts(matrix)
        versions = [
            (_codepoint(key), tier, key)
            for key, tier in eligible.items()
            if key.startswith("version:")
        ]
        ciphers = sorted(
            _codepoint(key) for key in eligible if key.startswith("cipher:")
        )
        cipher_sessions: dict[int, set[str]] = {}
        for key in eligible:
            if key.startswith("cipher:"):
                cipher_sessions.setdefault(_codepoint(key), set()).update(
                    matrix[key].get("positive_evidence", ())
                )
        groups = sorted(
            _codepoint(key) for key in eligible if key.startswith("group:")
        )

        suites: dict[int, dict] = {}
        for cipher in ciphers:
            algorithm_refs = []
            for definition in registry.cipher_algorithms(cipher):
                algorithm_refs.append(algorithm(
                    definition["name"],
                    definition["primitive"],
                    definition.get("mode"),
                ))
            suites[cipher] = {
                "name": registry.cipher_name(cipher),
                "algorithms": algorithm_refs,
                "identifiers": [
                    f"0x{cipher >> 8:02X}",
                    f"0x{cipher & 0xFF:02X}",
                ],
            }

        for group in groups:
            definition = registry.group_cbom(group)
            if definition is not None:
                algorithm(
                    definition["name"],
                    definition["primitive"],
                    pq_level=definition.get("nist_quantum_security_level"),
                )

        for version, tier, version_key in sorted(versions):
            # Matrix cells are per capability; a version/suite pairing exists
            # only where one session selected both. Crossing every demonstrated
            # suite with every demonstrated version asserts unobserved pairs.
            version_sessions = set(
                matrix[version_key].get("positive_evidence", ())
            )
            paired = [
                cipher for cipher in ciphers
                if version_sessions & cipher_sessions[cipher]
            ]
            unknown_suites = [
                f"0x{cipher:04X}" for cipher in paired
                if not registry.known_cipher(cipher)
            ]
            version_label = registry.protocol_version(version)
            ref = _ref(
                "protocol",
                f"TLS-{version_label}@{server['server_id']}",
            )
            component = {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f"TLS {version_label}",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls",
                        "version": version_label,
                        "cipherSuites": [suites[cipher] for cipher in paired],
                    },
                },
                "properties": [
                    {"name": "netra:server", "value": server["server_id"]},
                    {"name": "netra:evidence_tier", "value": tier.value},
                    {"name": "netra:capture_sha256", "value": capture_sha256},
                ],
            }
            if unknown_suites:
                # CycloneDX 1.6 forbids properties on a cipherSuite object.
                component["properties"].append({
                    "name": "netra:unidentified_ciphers",
                    "value": ",".join(unknown_suites),
                })
            components[ref] = component

    metadata = {
        "tools": {
            "components": [{
                "type": "application",
                "name": "NETRA",
                "version": tool_version,
            }],
        },
        "properties": [
            {
                "name": "netra:source",
                "value": "passive observation of network traffic",
            },
            {
                "name": "netra:inclusion_rule",
                "value": "only OBSERVED or DEDUCED facts",
            },
            {"name": "netra:registry_version", "value": str(registry.version)},
        ],
    }
    timestamp = capture.get("last_ts") or capture.get("first_ts")
    if timestamp:
        metadata["timestamp"] = timestamp

    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"securemailscope:cbom:{capture_sha256}",
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": [components[key] for key in sorted(components)],
    }
