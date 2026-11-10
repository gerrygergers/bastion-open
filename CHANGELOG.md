# Changelog

## v0.2.0 — 2026-11-10 (the "commercial grade" pass)

Added
- Configuration benchmark: 10 high-precision static checks (sshd root/empty
  passwords/X11, world-writable system dirs, shadow + sudoers modes, sticky
  /tmp, world-writable cron files, empty-password and UID-0 accounts, suid
  core dumps). Every finding cites the file and the fix.
- Baseline diffing: first scan is a silent census; report marks NEW crit/high
  with `*` and `resolved_since_last=` counts drift. No more day-one alarm spam.
- Alert webhooks (ntfy / Slack-compatible JSON), strictly alert-on-NEW
  crit/high/KEV, at most once per finding ever.
- TLS certificate expiry probe for `urls:` targets (<14d = finding).
- Agentless ssh fleet scanning (`ssh:` targets) — streams our own collector,
  nothing installed on targets. docs/REMOTE.md covers the trust model.
- RPM inventory without executing host binaries (sqlite + ndbxdbc readers) and
  OSV distro ecosystems for Fedora/Rocky/Alma (best-effort, gap-flagged).
- `bastion.py` one-entrypoint CLI (scan/status/report/fix/version),
  `./install.sh` one-command install with docker/podman/native detection,
  systemd timer + cron examples in deploy/, Makefile, scripts/selftest.py
  (stdlib-only CI), docs/SECURITY-MODEL.md.
- Exit codes now carry meaning: 2 config, 10 CI-trigger findings, 20 internal
  failure — a dead scanner can never look like a clean host.

Changed
- dpkg version comparator rewritten; now differential-tested against real
  `dpkg --compare-versions` (21/21 on the battery incl. '~', epochs, 1.10>1.9).
- Policy: bare "critical" without CVSS score now SOAKS (urgent = KEV or
  critical AND CVSS≥9) — matches the discipline shipped 2026-11-10.
- Scanner container: cap_drop ALL + cap_add DAC_READ_SEARCH, read-only rootfs,
  no-new-privileges; documented why (and the degraded mode without the cap).
- trivy download verified against the release's published checksums at build
  time; pyyaml pinned; curl/xz purged from the final layer.
- Atomic cache writes (os.replace) everywhere; corrupt/old-shape caches rebuild.
- sshd config parsing honours sshd_config.d drop-ins (first-match semantics).
- URL probes: -L follows redirects, TLS expiry via openssl; no -k anymore.
- Inventory tarballs never contain private key material (name-pattern exclude,
  both transports) and pack procfs CONTENT correctly (size-0 stat trap).
- tar extraction rejects traversal/link/device members.

## v0.1.x — 2026-11-09

- Initial portable core: host OS CVEs via OSV, KEV overlay, chroot-apt fixer
  behind double gates, stable digests.
