"""Order-independent server capability constraints.

The inference functions consume small, redacted mappings;
captured application data never enters the constraint engine.
"""

from __future__ import annotations

from collections import defaultdict
from enum import Enum
from typing import Iterable, Mapping

from ..judgement.epistemic import Tier


class State(str, Enum):
    """The four states a capability cell can hold.

    There is deliberately no weak-exclusion state. Non-selection under server or
    unknown cipher ordering proves nothing -- the server never had to consider
    the suite -- so this engine records no negative observation at all in that
    case rather than a weak one. Every negative it does record is firm, which is
    why an ``EXCLUDED_LIKELY`` state was removed: it had become unreachable, and
    a state that can never be produced is a claim the report cannot support.
    """

    DEMONSTRATED = "DEMONSTRATED"
    EXCLUDED_FIRM = "EXCLUDED_FIRM"
    CONTRADICTED = "CONTRADICTED"
    UNDETERMINED = "UNDETERMINED"


class Mode(str, Enum):
    SERVER_ORDER = "server_order"
    CLIENT_ORDER = "client_order"
    UNKNOWN = "unknown"


# Coverage is measured against this protocol universe, not the cells that
# happened to be created by one capture.
APPLICABLE_VERSIONS = [0x0301, 0x0302, 0x0303, 0x0304]


def detect_preference_mode(sessions: Iterable[Mapping]) -> tuple[Mode, dict]:
    """Conclude a preference mode only when the alternative is ruled out.

    Two opposite-order clients receiving the same suite do not establish
    server order unless another shared suite has separately been demonstrated.
    A server supporting only the selected suite explains the same observation.
    """
    sessions = list(sessions)
    demonstrated = {
        session["selected_cipher"]
        for session in sessions
        if session.get("selected_cipher") is not None
    }
    by_signature: dict[tuple[int, ...], set[int]] = defaultdict(set)
    signature_sessions: dict[tuple[int, ...], set[str]] = defaultdict(set)
    for session in sessions:
        offered = session.get("offered_ciphers")
        selected = session.get("selected_cipher")
        if offered and selected is not None:
            signature = tuple(offered)
            by_signature[signature].add(selected)
            signature_sessions[signature].add(str(session["id"]))

    signatures = list(by_signature.items())
    for index, (first, first_selected) in enumerate(signatures):
        for second, second_selected in signatures[index + 1:]:
            shared = set(first) & set(second)
            if len(shared) < 2:
                continue
            first_order = [cipher for cipher in first if cipher in shared]
            second_order = [cipher for cipher in second if cipher in shared]
            if (first_order == second_order or len(first_selected) != 1
                    or len(second_selected) != 1):
                continue
            selected_first = next(iter(first_selected))
            selected_second = next(iter(second_selected))
            pair_evidence = {
                "shared": sorted(shared),
                "sessions": sorted(
                    signature_sessions[first] | signature_sessions[second]
                ),
            }

            if (selected_first == first_order[0]
                    and selected_second == second_order[0]
                    and selected_first != selected_second):
                return Mode.CLIENT_ORDER, pair_evidence

            if selected_first == selected_second:
                alternatives = shared - {selected_first}
                proven = alternatives & demonstrated
                if proven:
                    return Mode.SERVER_ORDER, {
                        **pair_evidence,
                        "alternative_proven": sorted(proven),
                    }
    return Mode.UNKNOWN, {
        "reason": "no pair rules out the alternative explanation",
    }


def build_support_matrix(sessions: Iterable[Mapping], mode: Mode) -> dict:
    """Build the capability matrix in two passes.

    Pass one gathers every positive and negative observation.  Pass two derives
    states from the complete evidence sets, making contradictions independent
    of session arrival order.
    """
    positive: dict[str, list[dict]] = defaultdict(list)
    # Every entry here is a firm exclusion; see State. Nothing weaker is recorded.
    negative: dict[str, list[dict]] = defaultdict(list)
    capabilities: set[str] = set()

    def establishing(session: Mapping, evidence_key: str, code: int,
                     kind: str) -> list[dict]:
        evidence = session.get(evidence_key, {})
        items = evidence.get(code, []) if isinstance(evidence, Mapping) else evidence
        return [
            {
                "session": str(session["id"]),
                "frame": item["frame"],
                "byte_offset": item["byte_offset"],
                "byte_length": item.get("byte_length", 2),
                "kind": kind,
            }
            for item in items
            if isinstance(item, Mapping)
            and isinstance(item.get("frame"), int)
            and isinstance(item.get("byte_offset"), int)
        ]

    for session in sessions:
        selected_version = session.get("selected_version")
        offered_versions = session.get("offered_versions", [])
        capabilities.update(
            f"version:{offered_version:#06x}" for offered_version in offered_versions
        )
        if selected_version is not None:
            selected_key = f"version:{selected_version:#06x}"
            capabilities.add(selected_key)
            positive[selected_key].extend(establishing(
                session, "selected_version_evidence", selected_version, "selected"
            ))
            for offered_version in offered_versions:
                offered_key = f"version:{offered_version:#06x}"
                capabilities.add(offered_key)
                if offered_version > selected_version and not (
                        offered_version >= 0x0304 and session.get("tls13_offer_unusable")):
                    # Negotiation always takes the highest mutual version, so an
                    # offer above the selection is firmly excluded -- unless the
                    # client's TLS 1.3 offer lacked what a server needs to take it.
                    negative[offered_key].extend(establishing(
                        session, "offered_version_evidence", offered_version, "offered"
                    ))

        selected_cipher = session.get("selected_cipher")
        offered_ciphers = session.get("offered_ciphers", [])
        capabilities.update(
            f"cipher:{offered_cipher:#06x}" for offered_cipher in offered_ciphers
        )
        if selected_cipher is not None:
            selected_key = f"cipher:{selected_cipher:#06x}"
            capabilities.add(selected_key)
            positive[selected_key].extend(establishing(
                session, "selected_cipher_evidence", selected_cipher, "selected"
            ))
            if selected_cipher in offered_ciphers:
                selected_index = offered_ciphers.index(selected_cipher)
                for offered_cipher in offered_ciphers:
                    if offered_cipher == selected_cipher:
                        continue
                    offered_key = f"cipher:{offered_cipher:#06x}"
                    capabilities.add(offered_key)
                    # Under client ordering, a suite ranked above the selection
                    # that the server passed over is firmly excluded. With server
                    # or unknown ordering, non-selection alone proves nothing, so
                    # nothing is recorded -- not a weaker exclusion.
                    if (mode == Mode.CLIENT_ORDER
                            and offered_ciphers.index(offered_cipher) < selected_index):
                        negative[offered_key].extend(establishing(
                            session, "offered_cipher_evidence", offered_cipher, "offered"
                        ))

        selected_group = session.get("selected_group")
        if selected_group is not None:
            # A selected key-share group is demonstrated. Other offered groups
            # were merely not chosen, which proves nothing, so none is recorded.
            selected_key = f"group:{selected_group:#06x}"
            capabilities.add(selected_key)
            positive[selected_key].extend(establishing(
                session, "selected_group_evidence", selected_group, "selected"
            ))

    matrix = {}
    for key in sorted(capabilities | set(positive) | set(negative)):
        positive_evidence = positive.get(key, [])
        negative_evidence = negative.get(key, [])
        if positive_evidence and negative_evidence:
            state = State.CONTRADICTED
        elif positive_evidence:
            state = State.DEMONSTRATED
        elif negative_evidence:
            state = State.EXCLUDED_FIRM
        else:
            state = State.UNDETERMINED
        tier = {
            State.DEMONSTRATED: Tier.OBSERVED,
            State.EXCLUDED_FIRM: Tier.DEDUCED,
            State.CONTRADICTED: Tier.DEDUCED,
            State.UNDETERMINED: Tier.NOT_OBSERVABLE,
        }[state]
        matrix[key] = {
            "state": state.value,
            "tier": tier.value,
            "positive_evidence": sorted({item["session"] for item in positive_evidence}),
            "negative_evidence": sorted({item["session"] for item in negative_evidence}),
            "establishing_evidence": sorted(
                positive_evidence + negative_evidence,
                key=lambda item: (
                    item["session"], item["frame"], item["byte_offset"], item["kind"]
                ),
            ),
        }
        if state == State.UNDETERMINED:
            matrix[key]["reason_code"] = "not_present_in_capture"
    return matrix


def deduced_coverage(matrix: Mapping[str, Mapping]) -> dict:
    """Report firmly settled versions over the applicable version universe."""
    settled = sum(
        1
        for version in APPLICABLE_VERSIONS
        if matrix.get(f"version:{version:#06x}", {}).get("state")
        in (State.DEMONSTRATED.value, State.EXCLUDED_FIRM.value)
    )
    return {
        "settled": settled,
        "applicable": len(APPLICABLE_VERSIONS),
        "percent": round(100 * settled / len(APPLICABLE_VERSIONS)),
    }


def find_contradictions(matrix: Mapping[str, Mapping]) -> list[dict]:
    """Return every capability carrying positive and firm-negative evidence."""
    contradictions = []
    for capability in sorted(matrix):
        cell = matrix[capability]
        if cell.get("state") != State.CONTRADICTED.value:
            continue
        contradictions.append({
            "capability": capability,
            "demonstrated_in": list(cell.get("positive_evidence", [])),
            "excluded_in": list(cell.get("negative_evidence", [])),
            "possible_causes": [
                "load balancer with inconsistently configured backends",
                "TLS interception presenting as the same endpoint",
                "server configuration changed during the capture",
            ],
        })
    return contradictions
