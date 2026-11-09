# bastion-open

Security auditing for your own machines, in one Docker container. Point it at a
Linux host, it lists every installed package, cross-checks against OSV and CISA's
known-exploited list, flags vulnerable packages, probes your public URLs, and
writes a report. Detect-and-report by default — fixing is opt-in and gated.

Born as "bastion", a personal 11-module security suite running on a homelab
server. This is the portable core, stripped of any one person's fleet, creds and
hostname quirks.

## Quick start (30 seconds)

```bash
git clone https://github.com/YOU/bastion-open && cd bastion-open
docker compose run --rm scanner
```

That's it: build image, mount `/` read-only, audit, print the digest, leave.

## What it checks

| Check | How |
|---|---|
| Host OS CVEs | dpkg inventory -> OSV (Ubuntu/Debian). Linux meta-packages skipped; `linux-libc-dev` kept. |
| Known-exploited | every finding cross-checked against CISA KEV; KEV hits print first |
| Reboot needed | `/var/run/reboot-required` |
| Pending updates | apt cache inspection (host and distro) |
| Exposed listeners | `/proc/net/tcp{,6}` on the mount — what's bound to 0.0.0.0 |
| Public URLs | list them in `config/config.yaml`; container curls each, 4xx/5xx/timeout = finding |
| Docker images / code | trivy targets (built into the image): `image:` or `fs:` entries in config |

## Configuration

Everything lives in `config/config.yaml` (copy from `config.example.yaml`).
With no config, it just audits the mounted host. No API keys, no accounts.

## Scheduling

`docker compose run --rm scanner` is idempotent and prints a stable `digest=`
line. Cron it weekly, or use a systemd timer:
```
04 30 * * *  cd /opt/bastion-open && docker compose run --rm scanner >> /var/log/bastion.log 2>&1
```
Same digest twice in a row = nothing changed, safe to skim the log only when it
moves. (Note: a run with a cold cache reports some severities as unknown until
OSV details are fetched; expect one digest drift in the first day, then
stability. The fix-cache guard means stale formats can't linger.)

## Fixing things

Out of the box this tool will never change a byte on your machine. The findings
report says exactly what to do (`docs/FIXING.md` covers the opt-in fixer,
which is `apt --only-upgrade` with a dry-run abort guard, behind two env gates
AND a separate compose profile, because "runs as root against your host" should
cost you two deliberate decisions, not zero).

## What it doesn't do (yet)

- ssh/agentless scanning of remote boxes (v0.2: optional ssh inventory like the
  original fleet mode)
- non-Debian host package inventory (RPM read exists but is best-effort; macOS/NAS: use trivy or the scanner on a Linux jumpbox)
- a UI. There's a text report; PRs welcome, but that way lies slop.

## Architecture

```
config/config.yaml   ->  scan.py  ->  bastion_core.py
                                       ├─ read_dpkg_status()  (no shell, no exec of host binaries)
                                       ├─ osv_batch()         (OSV semantics documented in-code;
                                       │                        trust them, don't re-derive)
                                       ├─ kev_set()           (CISA feed, cached 24h)
                                       ├─ probe_urls()
                                       └─ trivy (images/fs)
                                    -> state/last-scan.json + report.md + digest
fix.py (opt-in)     ->  reads last-scan, chroot apt --only-upgrade, journalled
```

## Relationship to bastion (the original)

This repo carries the gauntlet's scanning brain and the KEV/OSV plumbing. It
intentionally leaves behind: per-box ssh config, network-appliance/ticket/proxy
cron monitor-gating glue, and any specific machine. See `docs/BASTION.md` for the
full lineage.

## License

MIT. Go make your boxes boring.
