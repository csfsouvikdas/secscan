import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from secscan.cli import main

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as e:  # argparse errors
            code = e.code
    return code, out.getvalue(), err.getvalue()


class CLI(unittest.TestCase):
    def test_fails_on_vulnerable_examples(self):
        code, out, _ = run(EXAMPLES, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("Summary:", out)

    def test_fail_on_none(self):
        self.assertEqual(run(EXAMPLES, "--fail-on", "none")[0], 0)

    def test_clean_dir_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "ok.py"), "w") as fh:
                fh.write("print('hello')\n")
            code, out, _ = run(d, "--no-color")
            self.assertEqual(code, 0)
            self.assertIn("no findings", out)

    def test_missing_path(self):
        self.assertEqual(run("/definitely/not/here")[0], 2)

    def test_unknown_disable_id(self):
        self.assertEqual(run(EXAMPLES, "--disable", "NOPE1")[0], 2)

    def test_disable_rule(self):
        _, out, _ = run(EXAMPLES, "-f", "json", "--fail-on", "none", "--disable", "PY101")
        self.assertNotIn('"rule_id": "PY101"', out)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "r.sarif")
            code, _, err = run(EXAMPLES, "-f", "sarif", "-o", target, "--fail-on", "none")
            self.assertEqual(code, 0)
            self.assertTrue(os.path.getsize(target) > 100)
            self.assertIn("wrote sarif report", err)

    def test_list_rules(self):
        code, out, _ = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("SEC001", out)


if __name__ == "__main__":
    unittest.main()
