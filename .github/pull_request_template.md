## What changed

## Which invariant does this touch

Name the security invariant or decision affected, or "none".

## The mutation that proves the test bites

Break the thing under test, show the named test failing, then fix — a green test beside a check does not prove it tests that check.

## Checklist

- [ ] `make check-strict` is green
- [ ] no new dependency (or it was discussed in an issue first)
- [ ] no error string carries plaintext, a DEK, or private-key bytes
- [ ] Conventional Commit title
