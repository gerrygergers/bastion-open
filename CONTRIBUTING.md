# Contributing

Short version: bugs and features welcome, keep the two invariants.

1. **Read-only by default.** Scanner code must never mutate the target system.
   Remediation lives in `fix.py` behind its gates and stays that way.
2. **No machine-specific assumptions.** Paths come from env/config, distros are
   detected not assumed, and nothing may require a homelab, a VPN, or anyone's
   particular kernel version.

Practical notes:
- The OSV semantics in `bastion_core.osv_batch` are load-bearing and documented
  inline; "simplifying" them has broken real scans before. If you think one is
  wrong, prove it with a targeted query (the function docstring shows how).
- Tests use the fake-host pattern (fixture dir, no root, no network for parsing
  tests). Add one with every fix.
- `scan.py` output must stay deterministic and timestamp-free — the digest is a
  stability contract.
