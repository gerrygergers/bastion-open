# Changelog

## v0.2.1 — 2026-11-11 (adversarial-review pass)

Every finding from two independent code reviews (offensive security +
correctness) is closed, with regression tests for each:

Security
- All state/report writes are atomic replace (unique temp name); nothing is
  written in-place by the root-privileged scanner, so a planted symlink in the
  data dir can no longer turn a scan into a host root-write (local privesc).
- Fixer journal opens with O_NOFOLLOW + 0600.
- ssh fleet: host/user validated against a pinned charset — `-oProxyCommand=…`
  style config values are rejected instead of reaching ssh's argv (RCE).
  Remote temp inventory is O_EXCL (`set -C`) + unique; stale inventories are
  deleted before collect (a dead ssh can't pass as last week's clean scan).
- pack_inventory never follows symlinks (a plant in a globbed dir couldn't
  ship key material under an innocent name); fleet inventory tarball is pruned
  after scan so shadow hashes don't linger world-readable on the volume.
- sqlite URIs from remote filenames are quoted (`?` in a name can't drop
  mode=ro); apt/chroot package argv is `--`-terminated + Debian-charset
  validated (dash-prefixed names can't become apt options).
- State dir gets a 0750 default mode; webhook URLs scheme-gated.

Correctness
- FIXER WAS A NO-OP: `apt-get --only-upgrade X` is not a valid command.
  Now `apt-get install --only-upgrade --` (verified against a live dpkg tree).
- Debian point releases queried OSV as `Debian:12.5` = ZERO results, silent
  false-clean. Queries now use the serie (`Debian:12`); Ubuntu keeps its
  point-release ecosystem (verified both directions).
- Fedora/Rocky/Alma branch tested the wrong value (display name vs eco key) —
  was dead code; RPM distros now actually hit OSV, still gap-flagged on zero.
- Unversioned/codename-only releases (Debian sid) resolve via codename maps;
  anything that still can't be versioned emits a scan-gap, never a pass.
- Fixed OS-scoped fixer fallback that could apt-upgrade packages named by
  OTHER machines' findings: scope mismatch now means do nothing.
- AUTH-01/Auth-03 parse shadow field 2 exactly (was a regex that
  false-positives on hashed root, false-negatives the empty case); AUTH-02
  reads /etc/passwd UID, not shadow's date field.
- sshd drop-ins beat sshd_config (Include-first distro layouts) — no more
  false-clean PermitRootLogin.
- KEV membership now rotates the digest and re-alerts (a CVE flipping to
  known-exploited was previously invisible); resolved→reappears no longer
  re-alerts (permanent ever-baseline); policy queue entries clear when a pkg
  enters the apply path; alert filter honours the documented NEW-KEV contract.
- config-check dedupe keeps per-path instances (5 world-writable dirs = 5
  findings); trivy nonzero exit is a scan-gap, not clean; trivy cache HOME
  fixed for the read-only rootfs; url probing moved to urllib (curl is purged
  from the image — "HTTP 000" on every URL was the result) and TLS expiry
  parses openssl 3.x stdout (the old stderr grep was permanently dead);
  tcp6 `::ffff:0.0.0.0` wildcard constant corrected (docker-proxy binds);
  malformed YAML config exits 2 (config error), not 20; BASTION_EXIT_ON splits
  on commas; KEV-feed outage emits a scan-gap instead of silently disabling
  the KEV gate; ssh-branch package-db errors surface like the local branch.

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
