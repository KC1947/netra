from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from sms import m6_rules


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class RuleLoaderTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.rules_dir = Path(directory.name)
        rule_path = patch.object(m6_rules, "_RULES_DIR", self.rules_dir)
        rule_path.start()
        self.addCleanup(rule_path.stop)

    def copy_rule_file(self, filename):
        path = self.rules_dir / filename
        path.write_text((RULES_DIR / filename).read_text(encoding="utf-8"), encoding="utf-8")
        return path

    def test_registry_is_skipped_with_debug_logging_only(self):
        path = self.copy_rule_file("algorithms.yaml")
        with self.assertLogs("sms.m6_rules", level="DEBUG") as logs:
            self.assertEqual(m6_rules._load_rules(), {})
        self.assertEqual([record.levelname for record in logs.records], ["DEBUG"])
        self.assertIn(str(path), logs.output[0])

    def test_list_form_loads_every_rule_and_preserves_yaml_values(self):
        self.copy_rule_file("v15_signals.yaml")
        rules = m6_rules._load_rules()
        self.assertEqual(set(rules), {
            "TLS-DOWNGRADE-ANOMALY", "TLS-LEGACY-CLIENT", "TLS-FALLBACK-RETRY",
            "TLS13-NO-FORWARD-SECRECY", "TLS13-EARLY-DATA", "TLS-ECH-IN-USE",
            "TLS-NO-OCSP-STAPLING", "SERVER-INCONSISTENT",
        })
        self.assertEqual(rules["TLS-DOWNGRADE-ANOMALY"]["condition"],
                         "tls.downgrade_anomaly == true")
        self.assertIn("when it negotiates 1.2 or below.", rules["TLS-DOWNGRADE-ANOMALY"]["why"])
        self.assertEqual(rules["TLS13-EARLY-DATA"]["references"], ["RFC 8446 §2.3, §8"])
        self.assertEqual(rules["SERVER-INCONSISTENT"]["references"], [])

    def test_single_dict_rule_still_loads(self):
        self.copy_rule_file("tls_ver_deprecated.yaml")
        rules = m6_rules._load_rules()
        self.assertEqual(list(rules), ["TLS-VER-DEPRECATED"])
        rule = rules["TLS-VER-DEPRECATED"]
        self.assertEqual(rule["severity"], "high")
        self.assertEqual(float(rule["confidence"]), 1.0)
        self.assertEqual(rule["remediation_id"], "disable_legacy_tls")
        self.assertEqual(rule["references"], ["RFC 8996", "RFC 9325"])

    def test_malformed_rules_name_file_and_missing_field(self):
        legacy = yaml.safe_load((RULES_DIR / "tls_ver_deprecated.yaml").read_text())
        signal = yaml.safe_load((RULES_DIR / "v15_signals.yaml").read_text())[0]
        path = self.rules_dir / "malformed.yaml"
        for original in (legacy, signal):
            for as_list in (False, True):
                for field in original:
                    # A top-level mapping without rule_id is explicitly a data
                    # file. A missing rule_id inside a rule list is malformed.
                    if field == "rule_id" and not as_list:
                        continue
                    with self.subTest(rule=original["rule_id"], as_list=as_list, field=field):
                        malformed = {key: value for key, value in original.items() if key != field}
                        document = [original, malformed] if as_list else malformed
                        path.write_text(yaml.safe_dump(document), encoding="utf-8")
                        with self.assertRaises(ValueError) as error:
                            m6_rules._load_rules()
                        self.assertIn(str(path), str(error.exception))
                        self.assertIn(field, str(error.exception))

    def test_non_rule_documents_are_skipped(self):
        path = self.rules_dir / "data.yaml"
        for document in (
            None, "metadata", ["one", "two"], [], {"severity": "metadata"},
            [{"name": "x25519", "code": 0x001D}],
        ):
            with self.subTest(document=document):
                path.write_text(yaml.safe_dump(document), encoding="utf-8")
                with self.assertLogs("sms.m6_rules", level="DEBUG"):
                    self.assertEqual(m6_rules._load_rules(), {})

    def test_invalid_member_in_rule_pack_raises(self):
        rule = yaml.safe_load((RULES_DIR / "tls_ver_deprecated.yaml").read_text())
        path = self.rules_dir / "mixed.yaml"
        path.write_text(yaml.safe_dump([rule, "not a rule"]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, r"mixed\.yaml: rule 2 must be a mapping"):
            m6_rules._load_rules()

    def test_invalid_yaml_names_its_file(self):
        path = self.rules_dir / "broken.yaml"
        path.write_text("rule_id: [unterminated", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, r"broken\.yaml: invalid YAML"):
            m6_rules._load_rules()


if __name__ == "__main__":
    unittest.main()
