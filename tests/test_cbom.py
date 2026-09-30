"""Schema and epistemic-boundary checks for CycloneDX 1.6 export."""

from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from sms.delivery.cbom import build_cbom
from sms.judgement.epistemic import UntieredFactError
from sms.cli import main
from sms.pipeline import run_pipeline


class CbomTests(unittest.TestCase):
    def setUp(self):
        self.validator = JsonStrictValidator(SchemaVersion.V1_6)

    def test_sample_cbom_passes_strict_cyclonedx_16_schema(self):
        report = run_pipeline("out/sample.pcap", ml=False)
        cbom = build_cbom(report)
        self.assertIsNone(self.validator.validate_str(json.dumps(cbom)))

        corrupted = deepcopy(cbom)
        algorithm = next(
            component for component in corrupted["components"]
            if component["cryptoProperties"]["assetType"] == "algorithm"
        )
        algorithm["cryptoProperties"]["algorithmProperties"]["primitive"] = "banana"
        self.assertIsNotNone(
            self.validator.validate_str(json.dumps(corrupted))
        )

    def test_cli_writes_cbom(self):
        with TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            target = Path(directory) / "sample.cdx.json"
            exit_code = main([
                "analyse", "out/sample.pcap", "--cbom", str(target), "--no-ml",
            ])
            cbom = json.loads(target.read_text())
        self.assertEqual(exit_code, 0)
        self.assertIsNone(self.validator.validate_str(json.dumps(cbom)))

    def test_undetermined_and_inferred_facts_do_not_become_components(self):
        report = {
            "capture": {"sha256": "ab" * 32},
            "servers": [{
                "server_id": "mail.example@192.0.2.1:25",
                "support_matrix": {
                    "version:0x0303": {
                        "state": "DEMONSTRATED", "tier": "OBSERVED",
                    },
                    "version:0x0304": {
                        "state": "EXCLUDED_FIRM", "tier": "DEDUCED",
                    },
                    "cipher:0x1301": {
                        "state": "UNDETERMINED", "tier": "NOT_OBSERVABLE",
                    },
                    "cipher:0x1302": {
                        "state": "DEMONSTRATED", "tier": "INFERRED",
                    },
                    # A contradicted capability is not inventory: the server
                    # both demonstrated and firmly excluded it, so the CBOM must
                    # not assert it even though the tier is DEDUCED.
                    "cipher:0xc02f": {
                        "state": "CONTRADICTED", "tier": "DEDUCED",
                    },
                },
            }],
        }
        cbom = build_cbom(report)
        protocols = [
            component for component in cbom["components"]
            if component["cryptoProperties"]["assetType"] == "protocol"
        ]
        self.assertEqual(len(protocols), 1)
        self.assertEqual(protocols[0]["name"], "TLS 1.2")
        self.assertEqual(
            protocols[0]["cryptoProperties"]["protocolProperties"]["cipherSuites"],
            [],
        )
        self.assertFalse(any(
            component["cryptoProperties"]["assetType"] == "algorithm"
            for component in cbom["components"]
        ))

    def test_unknown_cipher_is_retained_and_flagged_on_protocol(self):
        # As in a real report, each cell names the sessions that established
        # it: s1 negotiated TLS 1.3 with the unidentified suite, s2 negotiated
        # TLS 1.2 with a known one. Only a shared session makes a pairing.
        report = {
            "capture": {"sha256": "cd" * 32},
            "servers": [{
                "server_id": "192.0.2.2:465",
                "support_matrix": {
                    "version:0x0304": {
                        "state": "DEMONSTRATED", "tier": "DEDUCED",
                        "positive_evidence": ["s1"],
                    },
                    "cipher:0x9999": {
                        "state": "DEMONSTRATED", "tier": "OBSERVED",
                        "positive_evidence": ["s1"],
                    },
                    "version:0x0303": {
                        "state": "DEMONSTRATED", "tier": "OBSERVED",
                        "positive_evidence": ["s2"],
                    },
                    "cipher:0xc02f": {
                        "state": "DEMONSTRATED", "tier": "OBSERVED",
                        "positive_evidence": ["s2"],
                    },
                },
            }],
        }
        cbom = build_cbom(report)
        protocols = {
            component["name"]: component for component in cbom["components"]
            if component["cryptoProperties"]["assetType"] == "protocol"
        }
        tls13 = protocols["TLS 1.3"]
        suites = tls13["cryptoProperties"]["protocolProperties"]["cipherSuites"]
        self.assertEqual([suite["name"] for suite in suites], ["UNKNOWN_0x9999"])
        self.assertNotIn("properties", suites[0])
        self.assertIn(
            {"name": "netra:unidentified_ciphers", "value": "0x9999"},
            tls13["properties"],
        )
        # Never negotiated with TLS 1.2, so neither listed nor flagged there.
        tls12 = protocols["TLS 1.2"]
        self.assertEqual(
            [suite["name"] for suite in
             tls12["cryptoProperties"]["protocolProperties"]["cipherSuites"]],
            ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        )
        self.assertNotIn(
            "netra:unidentified_ciphers",
            [item["name"] for item in tls12["properties"]],
        )
        self.assertIsNone(self.validator.validate_str(json.dumps(cbom)))

    def test_untiered_matrix_fact_is_rejected(self):
        report = {
            "capture": {"sha256": "ef" * 32},
            "servers": [{
                "server_id": "192.0.2.3:993",
                "support_matrix": {
                    "version:0x0303": {"state": "DEMONSTRATED"},
                },
            }],
        }
        with self.assertRaises(UntieredFactError):
            build_cbom(report)


if __name__ == "__main__":
    unittest.main()
