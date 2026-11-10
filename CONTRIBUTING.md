# Contributing

Short version: bugs and features welcome, keep the three invariants.

1. **Read-only by default.** Scanner code must never mutate the target system.
   Remediation lives in `fix.py` behind its gates and stays that way.
2. **No machine-specific assumptions.** Paths come from env/config, distros are
   detected not assumed, and nothing may require a homelab, a VPN, or anyone's
   particular kernel version.
3. **Gaps are loud.** Anything a scan cannot check becomes a `scan-gap`
   finding. Silent partial coverage is a bug class of its own (see the
   dpkg-inventory-empty incident this rule came from).

Practical notes:
- The OSV semantics in `bastion_core.osv_batch` are load-bearing and documented
  inline; "simplifying" them has broken real scans before. If you think one is
  wrong, prove it with a targeted query (the function docstring shows how).
- `dpkg_cmp` is differential-tested against real dpkg; add cases to
  `scripts/selftest.py` if you touch it.
- Tests use the fake-host pattern (fixture dir, no root, no network for parsing
  tests). Add one with every fix. `make check` runs pytest + the stdlib-only
  selftest.
- `scan.py` stdout must stay deterministic and timestamp-free — the digest is a
  stability contract and cron-watchdogs diff it.
- Third-party downloads in the Dockerfile must be version-pinned AND
  checksum-verified at build time. No `curl | bash`, ever.
- Alerting changes must preserve alert-on-new-only. Users turn tools off when
  they cry wolf.
