# Contributing to SecScan

Thanks for helping improve the detection logic! 

## Quick start
```bash
git clone https://github.com/YOUR_USERNAME/secscan && cd secscan
pip install -e .
python -m unittest discover -s tests -v
```

## Adding or improving a rule
1. Add a `Rule(...)` to `src/secscan/rules.py` (regex rules need nothing else; Python AST rules also need a check in `pyast.py`).
2. Add **both** a positive test (it fires) and a negative test (safe code stays quiet) in `tests/test_scanner.py`.
3. If the rule is noisy on real code, tighten the pattern or add a `context` regex instead of lowering the severity.
4. Run `secscan src --fail-on high` - the project must scan itself cleanly.
5. Open a PR describing the weakness, the CWE, and a before/after example.

## Reporting false positives
Open an issue with the (sanitised) line of code and the rule ID. Never paste real secrets.
