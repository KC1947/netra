from pathlib import Path
import unittest

import yaml

from sms.judgement.conditions import ConditionError, evaluate


RULES = Path(__file__).resolve().parent.parent / "rules" / "v15_signals.yaml"


class ConditionTests(unittest.TestCase):
    def test_unsafe_or_malformed_conditions_are_rejected(self):
        facts = {"tls": {"x": 1}}
        for condition in (
            "__import__('os').system('ls')",
            "tls.x == 1 or True",
            "exec(1)",
            "tls.x ==",
        ):
            with self.subTest(condition=condition):
                with self.assertRaises(ConditionError):
                    evaluate(condition, facts)

    def test_every_signal_rule_condition_parses(self):
        rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))
        self.assertEqual(len(rules), 8)
        for rule in rules:
            with self.subTest(rule_id=rule["rule_id"]):
                result = evaluate(rule["condition"], {})
                self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()
