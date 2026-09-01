## What changed

## Security and privacy boundary

- [ ] No real credentials, proprietary source, or unredacted scan data is included.
- [ ] New or changed rules include paired vulnerable and safe benchmark fixtures.
- [ ] Remediation changes fail closed and include rollback tests.
- [ ] User-visible behavior and documentation are updated.

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `vulcanary . --offline --no-fail`
