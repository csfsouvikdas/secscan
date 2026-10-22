import json
import os
import tempfile
import unittest

from secscan.models import SEV_RANK
from secscan.reporters import render
from secscan.rules import RULES, RULES_BY_ID
from secscan.scanner import scan_paths, scan_text, shannon_entropy


def ids(code, name="x.py"):
    return {f.rule_id for f in scan_text(code, name, RULES)}


class RuleCatalogue(unittest.TestCase):
    def test_unique_ids_and_valid_severity(self):
        self.assertEqual(len(RULES), len({r.id for r in RULES}))
        for r in RULES:
            self.assertIn(r.severity, SEV_RANK)
            self.assertTrue(r.cwe.startswith("CWE-"))
            self.assertTrue(r.fix and r.description)


class PythonAst(unittest.TestCase):
    def test_eval_exec(self):
        self.assertIn("PY101", ids("eval(x)"))
        self.assertIn("PY101", ids("exec(code)"))

    def test_subprocess_shell(self):
        self.assertIn("PY102", ids("import subprocess\nsubprocess.run(cmd, shell=True)"))
        self.assertNotIn("PY102", ids("import subprocess\nsubprocess.run(['ls'], shell=False)"))
        self.assertIn("PY102", ids("import os\nos.system('ls ' + d)"))

    def test_alias_resolution(self):
        self.assertIn("PY103", ids("import pickle as p\np.loads(data)"))
        self.assertIn("PY102", ids("from os import system\nsystem('ls')"))

    def test_yaml(self):
        self.assertIn("PY104", ids("import yaml\nyaml.load(s)"))
        self.assertNotIn("PY104", ids("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)"))
        self.assertNotIn("PY104", ids("import yaml\nyaml.safe_load(s)"))

    def test_sql_injection(self):
        self.assertIn("PY106", ids("cur.execute(f\"SELECT * FROM t WHERE a={a}\")"))
        self.assertIn("PY106", ids("cur.execute('SELECT ' + col)"))
        self.assertIn("PY106", ids("cur.execute('SELECT %s' % col)"))
        self.assertNotIn("PY106", ids("cur.execute('SELECT * FROM t WHERE a=?', (a,))"))
        self.assertNotIn("PY106", ids("cur.execute('SELECT 1')"))

    def test_hashlib(self):
        self.assertIn("PY105", ids("import hashlib\nhashlib.md5(b'x')"))
        self.assertNotIn("PY105", ids("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)"))
        self.assertNotIn("PY105", ids("import hashlib\nhashlib.sha256(b'x')"))

    def test_template_injection(self):
        self.assertIn("PY108", ids("render_template_string('<p>' + name)"))
        self.assertNotIn("PY108", ids("render_template_string('<p>hi</p>')"))

    def test_except_pass(self):
        self.assertIn("PY109", ids("try:\n    x()\nexcept Exception:\n    pass"))

    def test_syntax_error_is_reported_not_raised(self):
        errors = []
        scan_text("def broken(:\n", "bad.py", RULES, errors)
        self.assertEqual(len(errors), 1)


class RegexRules(unittest.TestCase):
    def test_secrets(self):
        self.assertIn("SEC001", ids('k = "AKIAIOSFODNN7EXAMPLE"'))
        self.assertIn("SEC002", ids("-----BEGIN " + "RSA PRIVATE KEY-----", "k.pem.txt"))
        self.assertIn("SEC003", ids("t = 'ghp_" + "aB3" * 12 + "'"))
        self.assertIn("SEC006", ids('db_password = "hunter2hunter2"'))

    def test_placeholders_not_flagged(self):
        self.assertNotIn("SEC006", ids('password = "changeme"'))
        self.assertNotIn("SEC006", ids('api_key = "<your-api-key>"'))
        self.assertNotIn("SEC006", ids('token_type = "bearer"'))
        self.assertNotIn("SEC006", ids("password = os.environ['PW']"))

    def test_entropy(self):
        self.assertGreater(shannon_entropy("aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY"), 4.5)
        self.assertIn("SEC007", ids('x = "q8Vd2LmN7xT4pRz1WbK9sYc6HgJ3aFuE0oXiPn5B"'))
        self.assertNotIn("SEC007", ids('x = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'))

    def test_js_rules(self):
        self.assertIn("INJ101", ids('db.query("SELECT * FROM a WHERE b=\'" + x + "\'")', "a.js"))
        self.assertNotIn("INJ101", ids('db.query("SELECT * FROM a WHERE b=?", [x])', "a.js"))
        self.assertIn("INJ102", ids('exec("ls " + dir)', "a.js"))
        self.assertIn("INJ105", ids("eval(code)", "a.js"))
        self.assertIn("XSS101", ids("el.innerHTML = x", "a.js"))
        self.assertIn("CRY203", ids("{ rejectUnauthorized: false }", "a.ts"))

    def test_php_rules(self):
        self.assertIn("INJ106", ids("include($_GET['p']);", "a.php"))
        self.assertIn("XSS102", ids("echo $_GET['n'];", "a.php"))
        self.assertIn("DES301", ids("unserialize($x);", "a.php"))

    def test_context_gated_randomness(self):
        self.assertIn("CRY204", ids("const token = Math.random()", "a.js"))
        self.assertNotIn("CRY204", ids("const x = Math.random()", "a.js"))

    def test_config_rules(self):
        self.assertIn("CFG401", ids("DEBUG = True"))
        self.assertIn("CFG402", ids("ALLOWED_HOSTS = ['*']"))
        self.assertIn("CFG403", ids("os.chmod(p, 0o777)"))

    def test_comments_skipped_for_code_rules_but_not_secrets(self):
        self.assertNotIn("PY101", ids("# eval(x)"))
        self.assertNotIn("INJ105", ids("// eval(x)", "a.js"))
        self.assertIn("SEC001", ids("# AKIAIOSFODNN7EXAMPLE"))

    def test_clean_code_has_no_findings(self):
        clean = "import secrets\n\ndef token():\n    return secrets.token_hex(16)\n"
        self.assertEqual(ids(clean), set())


class Suppression(unittest.TestCase):
    def test_inline_ignore_all(self):
        self.assertEqual(ids("eval(x)  # secscan: ignore"), set())

    def test_inline_ignore_specific(self):
        self.assertEqual(ids("eval(x)  # secscan: ignore=PY101"), set())
        self.assertIn("PY101", ids("eval(x)  # secscan: ignore=PY999"))

    def test_nosec(self):
        self.assertEqual(ids("eval(x)  # nosec"), set())


class Redaction(unittest.TestCase):
    def test_secret_value_masked(self):
        f = scan_text('k = "AKIAIOSFODNN7EXAMPLE"', "a.py", RULES)[0]
        self.assertNotIn("IOSFODNN7EXAMPLE", f.snippet)
        self.assertIn("AKIA", f.snippet)


class FileScanning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "node_modules"))
        with open(os.path.join(self.root, "node_modules", "bad.js"), "w") as fh:
            fh.write("eval(x)")
        with open(os.path.join(self.root, "app.js"), "w") as fh:
            fh.write("eval(x)\n")
        with open(os.path.join(self.root, "blob.bin"), "wb") as fh:
            fh.write(b"\x00\x01eval(")
        with open(os.path.join(self.root, ".env"), "w") as fh:
            fh.write('API_KEY="abcdef123456"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_skips_vendor_and_binary(self):
        r = scan_paths([self.root], base=self.root)
        files = {f.file for f in r.findings}
        self.assertEqual(files, {"app.js", ".env"})

    def test_exclude_glob(self):
        r = scan_paths([self.root], excludes=["*.js"], base=self.root)
        self.assertEqual({f.file for f in r.findings}, {".env"})

    def test_min_severity(self):
        r = scan_paths([self.root], min_severity="critical", base=self.root)
        self.assertEqual(r.findings, [])

    def test_sorted_by_severity(self):
        r = scan_paths([self.root], base=self.root)
        ranks = [SEV_RANK[f.severity] for f in r.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class Reporters(unittest.TestCase):
    def setUp(self):
        self.result = scan_paths([os.path.join(os.path.dirname(__file__), "..", "examples")])

    def test_json(self):
        d = json.loads(render("json", self.result))
        self.assertEqual(d["tool"], "secscan")
        self.assertEqual(len(d["findings"]), len(self.result.findings))

    def test_sarif(self):
        d = json.loads(render("sarif", self.result))
        self.assertEqual(d["version"], "2.1.0")
        run = d["runs"][0]
        self.assertEqual(len(run["results"]), len(self.result.findings))
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue({r["ruleId"] for r in run["results"]} <= rule_ids)

    def test_html_escapes(self):
        from secscan.models import Finding, ScanResult
        evil = Finding("X1", "<script>t</script>", "high", "CWE-1", "<b>f</b>", 1, 1, "<img src=x onerror=1>", "d", "f")
        out = render("html", ScanResult(findings=[evil], files_scanned=1))
        self.assertNotIn("<img src=x", out)
        self.assertNotIn("<b>f</b>", out)
        self.assertIn("&lt;img", out)

    def test_markdown_and_console(self):
        self.assertIn("# SecScan report", render("markdown", self.result))
        self.assertIn("Summary:", render("console", self.result))


if __name__ == "__main__":
    unittest.main()
