# bastion-open

Security auditing for your own machines, in one Docker container. Point it at a
Linux host: it inventories every package, cross-checks OSV and CISA's
known-exploited list, runs a static configuration benchmark (sshd, file
permissions, auth), probes your public URLs and TLS certs, flags what it
couldn't check, and writes a report. Detect-and-report by default — fixing is
opt-in and triple-gated.

Born as "bastion", a personal 12-module security suite running on a homelab
server. This is the portable core, stripped of any one person's fleet, creds
and hostname quirks.

## Quick start (60 seconds)

```bash
git clone https://github.com/gerrygergers/bastion-open && cd bastion-open
./install.sh
```

…or the raw docker version, which is the same thing:

```bash
docker compose run --build --rm scanner
```

No config, no accounts, no API keys. Output: a digest line on stdout, full
report in `state/report.md` (volume `bastion-data`). Rerun prints the same
`digest=` when nothing changed.

## What it checks

| Check | How |
|---|---|
| Host OS CVEs | dpkg inventory -> OSV (Ubuntu/Debian strong; Fedora/Rocky/Alma via OSV distro ecosystems, best-effort). Linux meta-packages skipped; `linux-libc-dev` kept. |
| Known-exploited | every finding cross-checked against CISA KEV; KEV hits print first |
| Config benchmark | sshd settings, world-writable system dirs, `/etc/shadow` mode, empty/UID-0 password accounts, sticky /tmp, cron-file perms, suid core dumps — high-precision static checks, each cites the file |
| Reboot needed | `/var/run/reboot-required` |
| Exposed listeners | host `/proc/net/tcp{,6}` — what's bound to 0.0.0.0 |
| Public URLs | list them in `config/config.yaml`: HTTP status + TLS cert expiry (<14d = finding) |
| Docker images / code | trivy targets (built in, version-pinned + checksum-verified): `image:` or `fs:` entries |
| Remote Linux boxes | agentless over ssh — `ssh:` targets stream a small read-only inventory, nothing installed (docs/REMOTE.md) |
| Scan gaps | anything it couldn't check is a finding (`scan-gap`), never silence. A crashed scan exits 20. |

## Configuration

Everything lives in `config/config.yaml` (copy from `config.example.yaml`).
With no config, it just audits the mounted host.

## Scheduling & alerting

`docker compose run --rm scanner` is idempotent; cron it, or:

```bash
./install.sh --timer    # weekly systemd timer, 04:30 + jitter, Persistent
```

Silence-by-default is the design: same digest = nothing changed. Optional
webhooks (`alert:` in config) ping you ONLY about NEW critical/high findings —
ntfy.sh, Slack-compatible JSON. Cold start records a baseline silently (day
one is a census, not an alarm); after that, genuinely new crit/high alert.

## Fixing things

Out of the box this tool never changes a byte on your machine. The opt-in
fixer (`docs/FIXING.md`) requires a compose profile + two env gates + a
read-write host mount. `fix.py --dry-run` shows what it WOULD do with nothing
at stake. Even when enabled it applies by policy, not by reflex: KEV or
critical-with-CVSS≥9 immediately, everything else soaks 48h (fresh "fixes" are
where supply-chain poisoning hides), and packages under a curated incident
watch never auto-apply.

## Security model

Read `docs/SECURITY-MODEL.md` before pointing it at anything you care about.
Short version: the scanner container runs with all capabilities dropped except
one (for reading `/etc/shadow`), a read-only rootfs, and it never executes
binaries from the mounted host.

## What it doesn't do (yet)

- no runtime/IDS monitoring — it's an audit, not a sentinel between runs
- no web-app (DAST) or repo-secrets scanning
- macOS/Windows/appliances: out of scope for OS CVEs (probe their URLs, though)
- a UI. There's a text report; PRs welcome, but that way lies slop.

## Architecture

```
config/config.yaml  ->  scan.py ─┬─ bastion_core.py   inventory + OSV + KEV + benchmark
                                 ├─ trivy (targets)
                                 ├─ ssh fleet (docs/REMOTE.md)
                                 └─ baseline diff + webhooks (alert-on-new)
                              ->  state/{last-scan.json, report.md, digest, baseline.json}
fix.py (opt-in) -> policy.decide() -> chroot apt --only-upgrade, journalled
```

Stdlib-only Python 3.9+; runs directly on a host too (`BASTION_HOST=/
./bastion.py scan`). `make check` / `scripts/selftest.py` for the no-network
test paths.

## Relationship to bastion (the original)

This repo carries the scanning brain, the policy-gated fixer, and the config
benchmark. It intentionally leaves behind: per-box ssh config with real
hostnames, network-appliance integrations, ticket spines, and cron/agent glue.
See `docs/BASTION.md` for the lineage.

## License

MIT. Go make your boxes boring.
