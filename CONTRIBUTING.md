# Contributing to Nexus Security

Thanks for helping! The most valuable contributions are **new security rules**,
**false-positive reports**, and **language coverage**.

## Adding a security rule

Rules live in `engine/rules_security.py` as `SecurityRule` entries. Each one is a
single regex plus metadata:

```python
SecurityRule(
    "PY-EVAL-001",                    # unique ID: LANG-CATEGORY-NUMBER
    "eval() with user input",         # short title
    "critical",                       # critical | high | medium | low
    "CWE-95", "A03:2021",             # CWE + OWASP Top 10 category
    "command",                        # rule category
    ("python",),                      # languages it applies to
    _rx(r'\beval\s*\('),              # the pattern
    "eval() executes arbitrary code.",# description
    'eval(x)', "Avoid eval / use ast.literal_eval",  # before / after fix hint
),
```

### Rules for a good rule

1. **Precise.** It must not fire on safe code. Test against real examples.
2. **No catastrophic backtracking.** Avoid nested quantifiers like `(\w*)*` or
   `.*X.*` on unbounded input — they cause ReDoS. Add upper bounds (`{1,100}`).
3. **Real impact.** Map to an actual CWE. Don't add style nags as "security".
4. **One job.** One rule = one issue. Don't combine.

### Test your rule

```bash
cd engine
# should FIRE on vulnerable code:
echo 'eval(user_input)' > /tmp/vuln.py && python3 cli.py /tmp/vuln.py
# should stay SILENT on safe code:
echo 'x = 1 + 1' > /tmp/safe.py && python3 cli.py /tmp/safe.py
```

Also run the ReDoS check — no rule should take >0.3s on a 50k-char line:

```python
import time, rules_security
line = 'A' * 50000
for r in rules_security.ALL_RULES:
    t = time.time(); r.pattern.search(line)
    assert time.time() - t < 0.3, f"ReDoS in {r.id}"
```

## Reporting false positives

Open an issue with: the rule ID (shown in the finding), a minimal code snippet
that wrongly triggers it, and what the code actually does. These are gold —
precision is everything for a security tool.

## Pull requests

- One logical change per PR.
- Keep the engine dependency-free (standard library only).
- Run the examples in `examples/` to confirm nothing regressed.

## Code of conduct

Be respectful and constructive. We're building a tool people trust with their
security — accuracy and honesty matter more than feature count.

## License & contributions

Nexus is licensed under **AGPL-3.0**. By contributing, you agree your code is
licensed under the same terms.

Note: the project may offer a separate commercial license (see COMMERCIAL.md).
To keep that option open, significant contributions may require signing a simple
Contributor License Agreement (CLA) granting the maintainer the right to
relicense. This is standard for open-core projects and keeps the project
sustainable.
