"""Regression checks for the passive analysis engine.

Private hello parsers and reassembly are exercised directly, with fixtures
adapted to the engine's contracts.
IPv6 address handling is exercised through the actual PCAP ingest entry point.
Missing targets are expected failures; failures in existing targets remain red.
"""

from pathlib import Path
from tempfile import TemporaryDirectory
import math
import unittest

import numpy as np
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from sms.contracts import PacketObservation, Session
from sms.m1_ingest import _reassemble, ingest_pcap
from sms.m4_tls import _parse_client_hello, _parse_server_hello


A, B = 0xC02F, 0x002F


def observations(segments):
    """Adapt (sequence, frame, payload) fixtures to engine inputs."""
    return [
        PacketObservation(frame, "client_to_server", 0.0, seq, payload, 54)
        for seq, frame, payload in segments
    ]


class RegressionTests(unittest.TestCase):
    def test_01_preference_mode_not_identifiable_stays_unknown(self):
        from sms.correlation.constraints import detect_preference_mode

        sessions = [
            dict(id="s1", offered_ciphers=[A, B], selected_cipher=A),
            dict(id="s2", offered_ciphers=[B, A], selected_cipher=A),
        ]
        mode, _ = detect_preference_mode(sessions)
        self.assertEqual(mode.value, "unknown")

    def test_01b_server_order_when_alternative_proven_supported(self):
        from sms.correlation.constraints import detect_preference_mode

        sessions = [
            dict(id="s1", offered_ciphers=[A, B], selected_cipher=A),
            dict(id="s2", offered_ciphers=[B, A], selected_cipher=A),
            dict(id="s3", offered_ciphers=[B], selected_cipher=B),
        ]
        mode, _ = detect_preference_mode(sessions)
        self.assertEqual(mode.value, "server_order")

    def test_01c_client_order_detected(self):
        from sms.correlation.constraints import detect_preference_mode

        sessions = [
            dict(id="s1", offered_ciphers=[A, B], selected_cipher=A),
            dict(id="s2", offered_ciphers=[B, A], selected_cipher=B),
        ]
        mode, _ = detect_preference_mode(sessions)
        self.assertEqual(mode.value, "client_order")

    def test_02a_one_session_does_not_show_full_deduced_coverage(self):
        from sms.correlation.constraints import (
            Mode, build_support_matrix, deduced_coverage,
        )

        matrix = build_support_matrix([
            dict(id="s1", offered_ciphers=[A], selected_cipher=A,
                 selected_version=0x0303, offered_versions=[0x0303]),
        ], Mode.UNKNOWN)
        self.assertLess(deduced_coverage(matrix)["percent"], 100)

    def test_02b_contradiction_is_order_independent(self):
        from sms.correlation.constraints import Mode, build_support_matrix

        def evidence(frame, byte_offset):
            return {"frame": frame, "byte_offset": byte_offset, "byte_length": 2}

        x = dict(id="x", offered_ciphers=[A, B], selected_cipher=B,
                 offered_versions=[0x0303], selected_version=0x0303,
                 selected_cipher_evidence=[evidence(2, 50)],
                 offered_cipher_evidence={A: [evidence(1, 40)], B: [evidence(1, 42)]})
        y = dict(id="y", offered_ciphers=[A], selected_cipher=A,
                 offered_versions=[0x0303], selected_version=0x0303,
                 selected_cipher_evidence=[evidence(4, 50)],
                 offered_cipher_evidence={A: [evidence(3, 40)]})
        first = build_support_matrix([x, y], Mode.CLIENT_ORDER)
        second = build_support_matrix([y, x], Mode.CLIENT_ORDER)
        self.assertEqual(first[f"cipher:{A:#06x}"]["state"], "CONTRADICTED")
        self.assertEqual(second[f"cipher:{A:#06x}"]["state"], "CONTRADICTED")
        self.assertEqual(len(first[f"cipher:{A:#06x}"]["establishing_evidence"]), 2)

    def test_02c_support_claim_without_frame_is_undetermined(self):
        from sms.correlation.constraints import Mode, build_support_matrix

        matrix = build_support_matrix([
            dict(id="s1", offered_ciphers=[A], selected_cipher=A),
        ], Mode.UNKNOWN)
        self.assertEqual(matrix[f"cipher:{A:#06x}"]["state"], "UNDETERMINED")
        self.assertEqual(matrix[f"cipher:{A:#06x}"]["establishing_evidence"], [])
        self.assertEqual(
            matrix[f"cipher:{A:#06x}"]["reason_code"], "not_present_in_capture"
        )

    def test_02d_one_observed_sni_stabilises_the_same_endpoint(self):
        from sms.correlation.servers import correlate_servers

        def session(session_id, ip, hostname=None):
            item = Session(session_id, {
                "client_ip": "192.0.2.10", "client_port": 40000,
                "server_ip": ip, "server_port": 993, "transport": "tcp",
            })
            item._sni_hostname = hostname
            item._sni_evidence = []
            return item

        servers = correlate_servers([
            session("s1", "192.0.2.20", "imap.example"),
            session("s2", "192.0.2.20"),
            session("s3", "192.0.2.30"),
        ])
        self.assertEqual([item["server_id"] for item in servers], [
            "imap.example@192.0.2.20:993", "192.0.2.30:993",
        ])
        associated = next(
            item for item in servers[0]["identity_evidence"] if item["session"] == "s2"
        )
        self.assertEqual(associated["source"], "endpoint_sni_association")
        self.assertEqual(associated["tier"], "DEDUCED")
        self.assertFalse(associated["name_observed"])
        self.assertIn("not observed in this session", associated["reason"])
        bare = servers[1]["identity_evidence"][0]
        self.assertIsNone(bare["hostname"])
        self.assertIn("no server name was observed", bare["reason"])

    def test_03a_conflicting_retransmission_is_flagged(self):
        stream = _reassemble(observations([
            (1000, 1, b"AAAA"), (1000, 2, b"BBBB"),
        ]))
        # The existing reassembler must report conflicts; do not supply a
        # test-side default that would hide the missing diagnostic.
        self.assertTrue(hasattr(stream, "conflicts"),
                        "_reassemble returns no conflict diagnostics")
        self.assertEqual(len(stream.conflicts), 4)

    def test_03b_bytes_across_a_hole_are_not_concatenated(self):
        stream = _reassemble(observations([
            (1000, 1, b"AAAA"), (1010, 2, b"BBBB"),
        ]))
        self.assertEqual([data for data, _ in stream.iter_spans()],
                         [b"AAAA", b"BBBB"])

    def test_03c_consistent_partial_overlap_has_no_hole_or_conflict(self):
        stream = _reassemble(observations([
            (1000, 1, b"AAAA"), (1002, 2, b"AAXX"), (1006, 3, b"YY"),
        ]))
        self.assertEqual(len(stream.gaps), 0)
        self.assertEqual(stream.contiguous_bytes(), b"AAAAXXYY")
        self.assertTrue(hasattr(stream, "conflicts"),
                        "_reassemble returns no conflict diagnostics")
        self.assertEqual(len(stream.conflicts), 0)

    def test_03d_syn_retransmission_keeps_flow_and_port_reuse_splits_it(self):
        from sms.m1_ingest import FlowTable

        table = FlowTable()
        endpoints = ("10.0.0.1", 40001, "10.0.0.2", 25)
        first = table.key_for(endpoints, syn=True, rst=False, seq=5000)
        retransmit = table.key_for(endpoints, syn=True, rst=False, seq=5000)
        reused = table.key_for(endpoints, syn=True, rst=False, seq=9999)
        self.assertEqual(first, retransmit)
        self.assertNotEqual(first, reused)

    def test_03e_ipv6_addresses_parsed(self):
        # sms extracts addresses inline in ingest_pcap rather than through
        # the reference addr() helper. Exercise that existing implementation.
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IPv6(src="2001::1", dst="2001::2")
            / TCP(sport=40001, dport=25, flags="S", seq=5000)
        )
        packet.time = 0
        with TemporaryDirectory() as directory:
            path = Path(directory) / "ipv6.pcap"
            wrpcap(str(path), [packet])
            sessions = ingest_pcap(path)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].five_tuple["client_ip"], "2001::1")
        self.assertEqual(sessions[0].five_tuple["server_ip"], "2001::2")

    # Missing targets: sms.m1_ingest.FlowTable.add() and Budget.
    @unittest.expectedFailure
    def test_04a_total_buffered_bytes_obey_global_budget(self):
        from sms.m1_ingest import Budget, FlowTable

        table = FlowTable(Budget(total_bytes=10_000, bytes_per_flow=2_000,
                                 segments_per_flow=50, max_flows=100))
        for flow in range(200):
            for segment in range(100):
                table.add(("h", flow, "s", 25, 0), segment, segment, b"x" * 64)
        self.assertLessEqual(table.total, 10_000)

    # Missing targets: sms.m1_ingest.FlowTable.add() and Budget.
    @unittest.expectedFailure
    def test_04b_evictions_and_truncations_are_reported(self):
        from sms.m1_ingest import Budget, FlowTable

        table = FlowTable(Budget(total_bytes=10_000, bytes_per_flow=2_000,
                                 segments_per_flow=50, max_flows=100))
        for flow in range(200):
            for segment in range(100):
                table.add(("h", flow, "s", 25, 0), segment, segment, b"x" * 64)
        self.assertGreater(len(table.evicted), 0)
        self.assertGreater(table.truncated, 0)

    # Missing targets: sms.m1_ingest.FlowTable.key_for(), FlowTable.add(), Budget.
    @unittest.expectedFailure
    def test_04c_generation_map_is_bounded_with_flows(self):
        from sms.m1_ingest import Budget, FlowTable

        table = FlowTable(Budget(max_flows=2))
        for index in range(10):
            endpoints = ("h", 40000 + index, "s", 25)
            key = table.key_for(endpoints, True, False, index)
            table.add(key, index, index, b"x")
        self.assertLessEqual(len(table.gen), 2)

    def test_05_certificate_association_preserves_not_observable(self):
        from sms.m5_x509 import associate_certificates

        tls12 = dict(id="s1", certificate={
            "status": "VALID", "fingerprint": "aa", "frame": 14,
        })
        tls13 = dict(id="s2", certificate={"status": "NOT_OBSERVABLE"})
        associate_certificates([tls12, tls13])
        self.assertEqual(tls13["certificate"]["status"], "NOT_OBSERVABLE")
        self.assertTrue(tls13["certificate_seen_on_service"])

    # Missing function: sms.m7_anomaly.expected_calibration_error.
    @unittest.expectedFailure
    def test_06_all_wrong_probability_one_predictions_have_ece_one(self):
        from sms.m7_anomaly import expected_calibration_error

        ece = expected_calibration_error(np.zeros(20), np.ones(20))
        self.assertLess(abs(ece - 1.0), 1e-9)

    def test_07a_empty_server_hello_returns_structured_truncation(self):
        parsed = _parse_server_hello(b"")
        self.assertIn("parse_status", parsed)
        self.assertEqual(parsed["parse_status"], "truncated")

    def test_07b_grease_predicate_matches_exactly_sixteen_values(self):
        from sms.m4_tls import is_grease

        self.assertEqual(sum(is_grease(value) for value in range(0x10000)), 16)

    def test_07c_odd_cipher_vector_is_not_complete(self):
        odd = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x03"
               + b"\xc0\x2f\x00" + b"\x01\x00")
        parsed = _parse_client_hello(odd)
        self.assertIn("parse_status", parsed)
        self.assertNotEqual(parsed["parse_status"], "complete")

    def test_09a_all_three_reference_hybrid_groups_recognised(self):
        from sms.m4_tls import classify_group

        self.assertEqual([classify_group(group) for group in (0x11EB, 0x11EC, 0x11ED)],
                         ["PQ_HYBRID"] * 3)

    def test_09b_unrecognised_group_remains_unknown(self):
        from sms.m4_tls import classify_group

        self.assertEqual(classify_group(0x9999), "UNKNOWN")

    def test_09c_sentinel_severity_depends_on_clients_offered_versions(self):
        from sms.m4_tls import downgrade_finding

        legacy = downgrade_finding(
            {"offered_versions": [0x0303]},
            {"downgrade_sentinel": "settled_on_1.2"},
        )
        anomaly = downgrade_finding(
            {"offered_versions": [0x0304, 0x0303]},
            {"downgrade_sentinel": "settled_on_1.2"},
        )
        self.assertEqual(legacy["severity"], "info")
        self.assertEqual(anomaly["severity"], "high")

    def test_09d_tls13_psk_only_is_not_forward_secret(self):
        from sms.m4_tls import forward_secrecy

        self.assertEqual(forward_secrecy({
            "selected_version": 0x0304, "psk_selected": True, "selected_group": None,
        }, [0]), "NO")

    # Missing function: sms.m6_rules.verify_finding. That module also has the
    # pre-existing rule-loader import error documented in docs/AUDIT.md.
    @unittest.expectedFailure
    def test_10_absence_requires_a_probe_before_claiming_a_fix(self):
        from sms.m6_rules import verify_finding

        finding = {"capability": "version:0x0301"}
        not_probed = [dict(offered_versions=[0x0304, 0x0303], selected_version=0x0304)]
        probed = [dict(offered_versions=[0x0303, 0x0301], selected_version=0x0303)]
        still = [dict(offered_versions=[0x0301], selected_version=0x0301)]
        self.assertEqual(verify_finding(finding, not_probed).value, "not_reobserved")
        self.assertEqual(verify_finding(finding, probed).value, "verified_fixed")
        self.assertEqual(verify_finding(finding, still).value, "still_present")

    # Missing function: sms.m7_anomaly.load_verified_artifact (and ArtifactRejected).
    @unittest.expectedFailure
    def test_11_pickle_model_artifacts_are_refused(self):
        from sms.m7_anomaly import ArtifactRejected, load_verified_artifact

        with self.assertRaises(ArtifactRejected):
            load_verified_artifact("models/x.pkl", {})


if __name__ == "__main__":
    unittest.main()


class SupportStateSetTests(unittest.TestCase):
    """The matrix has four states. A fifth must not reappear undetected."""

    def test_state_set_is_exactly_four(self):
        from sms.correlation.constraints import State

        self.assertEqual({state.value for state in State}, {
            "DEMONSTRATED", "EXCLUDED_FIRM", "CONTRADICTED", "UNDETERMINED",
        })

    def test_every_state_the_engine_declares_is_reachable(self):
        """Guards against re-adding a state nothing can produce.

        EXCLUDED_LIKELY was declared, documented and tier-mapped while being
        unreachable, because negative evidence is only ever firm. Enumerating
        reachable states here means any future addition must come with a path
        that actually produces it.
        """
        from sms.correlation.constraints import Mode, State, build_support_matrix

        def evidence(code, frame, offset):
            return {code: [{"frame": frame, "byte_offset": offset, "byte_length": 2}]}

        def session(identifier, offered_ciphers, selected_cipher,
                    offered_versions, selected_version):
            return {
                "id": identifier,
                "offered_ciphers": list(offered_ciphers),
                "selected_cipher": selected_cipher,
                "offered_versions": list(offered_versions),
                "selected_version": selected_version,
                "selected_cipher_evidence": evidence(selected_cipher, 10, 10),
                "offered_cipher_evidence": {
                    cipher: [{"frame": 10, "byte_offset": 20, "byte_length": 2}]
                    for cipher in offered_ciphers
                },
                "selected_version_evidence": evidence(selected_version, 10, 2),
                "offered_version_evidence": {
                    version: [{"frame": 10, "byte_offset": 2, "byte_length": 2}]
                    for version in offered_versions
                },
            }

        # DEMONSTRATED + EXCLUDED_FIRM: offers 1.3, negotiates 1.2.
        downgraded = build_support_matrix(
            [session("a", [0x1301], 0x1301, [0x0304, 0x0303], 0x0303)], Mode.UNKNOWN
        )
        # CONTRADICTED: a second session to the same identity does get 1.3.
        contradicted = build_support_matrix(
            [session("a", [0x1301], 0x1301, [0x0304, 0x0303], 0x0303),
             session("b", [0x1301], 0x1301, [0x0304, 0x0303], 0x0304)], Mode.UNKNOWN
        )
        # UNDETERMINED: a suite the client offered while the server selected
        # nothing, so the capability is known of but neither proven nor excluded.
        unselected = session("a", [0x1301, 0xc02f], None, [0x0303], 0x0303)
        unselected["selected_cipher_evidence"] = {}
        undetermined = build_support_matrix([unselected], Mode.UNKNOWN)
        self.assertEqual(undetermined["cipher:0xc02f"]["state"],
                         State.UNDETERMINED.value)
        self.assertEqual(undetermined["cipher:0xc02f"]["reason_code"],
                         "not_present_in_capture")

        reachable = {cell["state"]
                     for matrix in (downgraded, contradicted, undetermined)
                     for cell in matrix.values()}
        self.assertEqual(reachable, {state.value for state in State})


class RegistryCompletenessTests(unittest.TestCase):
    """An unregistered suite must reach the engine as unknown, not as a negative."""

    CAPTURES = (
        "out/sample.pcap", "out/anomaly_demo.pcap", "out/multiclient.pcap",
        "out/baseline.pcap", "out/haystack.pcap",
        "tests/fixtures/real_mail.pcap", "tests/fixtures/mixed_enterprise.pcap",
        "tests/fixtures/recorded_mail_ethernet.pcapng",
    )

    def test_every_suite_in_every_shipped_capture_is_registered(self):
        """0xCCA9 was absent, so real_mail s7 was scored as 'not AEAD, not CBC'.

        Reads the suites straight out of the captures with tshark rather than
        from our own parser, so a parser gap cannot hide a registry gap.
        """
        import shutil
        import subprocess
        from pathlib import Path
        from sms.registry import load

        tshark = shutil.which("tshark")
        if tshark is None:
            self.skipTest("tshark not installed")
        root = Path(__file__).resolve().parents[1]
        registry = load()
        codes: set[int] = set()
        for capture in self.CAPTURES:
            path = root / capture
            if not path.exists():
                continue
            out = subprocess.run(
                [tshark, "-r", str(path), "-n", "-Y", "tls.handshake",
                 "-T", "fields", "-e", "tls.handshake.ciphersuite"],
                capture_output=True, text=True, check=False).stdout
            for line in out.splitlines():
                codes.update(int(code, 16) for code in line.split(",") if code.strip())
        self.assertGreater(len(codes), 20, "no suites extracted; check the tshark call")
        missing = sorted(code for code in codes if not registry.known_cipher(code))
        self.assertEqual(
            missing, [],
            "unregistered suites reach the anomaly layer as false negatives: "
            + ", ".join(f"0x{code:04X}" for code in missing),
        )

    def test_unregistered_suite_yields_unknown_not_false(self):
        from sms.m7_anomaly import _registry_flag

        for prop in ("aead", "cbc"):
            self.assertTrue(math.isnan(_registry_flag("UNKNOWN_0xABCD", prop)))
            self.assertTrue(math.isnan(_registry_flag(None, prop)))
        self.assertEqual(
            _registry_flag("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "aead"), 1.0)
        self.assertEqual(
            _registry_flag("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "cbc"), 0.0)

    def test_registry_props_never_inferred_from_the_suite_name(self):
        """The substring heuristic agreed with the registry by luck, not design."""
        from sms.registry import load

        registry = load()
        for code, entry in registry.ciphers.items():
            name = entry["name"]
            with self.subTest(cipher=f"0x{code:04X}"):
                self.assertEqual(bool(registry.cipher_has(code, "cbc")), "CBC" in name)
                self.assertEqual(
                    bool(registry.cipher_has(code, "aead")),
                    any(word in name for word in ("GCM", "CHACHA20", "CCM")),
                )


class StateVocabularyDriftTests(unittest.TestCase):
    """Nothing may keep its own copy of the support-state vocabulary.

    lab/verify_enterprise.py held a hardcoded five-state tuple that outlived the
    removal of EXCLUDED_LIKELY and kept printing it as a zero row, so the tool
    that proves the fixture matches its answer key contradicted the API contract.
    """

    def test_enterprise_verifier_takes_its_states_from_the_engine(self):
        from lab.verify_enterprise import MATRIX_STATES
        from sms.correlation.constraints import State

        self.assertEqual(set(MATRIX_STATES), {state.value for state in State})
        self.assertNotIn("EXCLUDED_LIKELY", MATRIX_STATES)

    def test_no_module_hardcodes_a_removed_state(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        # Engine and tooling sources must not hardcode obsolete support-state values.
        searched = [
            path for directory in ("sms", "lab", "ml", "server", "bench")
            for path in (root / directory).rglob("*.py")
            if "__pycache__" not in path.parts
        ]
        offenders = [
            f"{path.relative_to(root)}:{number}"
            for path in searched
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if '"EXCLUDED_LIKELY"' in line or "'EXCLUDED_LIKELY'" in line
        ]
        self.assertEqual(offenders, [],
                         f"removed state is still named as a value: {offenders}")
