# Security model (read me first)

This tool reads your whole filesystem and optionally changes packages. Here is
exactly what it does, what it touches, and where it can hurt you — because
"just run this random repo as root" is how people get pwned, including by
tools that mean well.

## Scanner (default, read-only)

- Runs as root inside the container with **all Linux capabilities dropped
  except `DAC_READ_SEARCH`** — the single cap needed to read host
  `/etc/shadow` for two high-value auth checks (root password hash, UID-0
  accounts). No SYS_ADMIN, no SETUID, no write syscalls beyond /tmp and the
  data volume. The container rootfs is `read_only: true`, no new privileges.
  (If even that cap is too much for your threat model, delete the `cap_add`
  line in compose: shadow-based checks emit scan-gaps instead of passes.)
- Reads from the mounted host: `/etc/os-release`, `/var/lib/dpkg/status`,
  `/etc/shadow`, `/etc/passwd`, `/etc/group`, `/etc/sudoers(.d)`,
  `/etc/ssh/sshd_config(.d)`, `/etc/cron.d`, `/proc/net/tcp{,6}`,
  `/var/run/reboot-required`, plus package metadata for trivy targets.
- It **never executes binaries from the mounted host** — inventory parsing is
  done in pure Python against the files themselves.
- Outbound HTTPS to: `api.osv.dev`, `cisa.gov` (KEV feed),
  `api.github.com` (malware-advisory feed for the fixer policy, cached 12h),
  and the `urls:` you configure. Nothing is uploaded — outbound traffic
  carries package *queries*, not results, and no identifiers.
- Plain `http://` is refused everywhere (enforced in `http_json`) unless you
  set `BASTION_ALLOW_HTTP=1`.

## Fixer (opt-in, deep gates — see docs/FIXING.md)

- Needs profile flag + two env vars + a read-write host mount. Runs apt
  `--only-upgrade` in a chroot. Never installs, removes, or edits config.
- Abort-guard: refuses any apt plan that would remove packages.
- Every decision goes through `policy.py`: KEV/critical+CVSS≥9 applies,
  everything else soaks 48h, packages under a supply-chain incident watch
  never auto-apply. All actions journaled to `state/journal.jsonl`.

## Fleet mode (ssh, docs/REMOTE.md)

Agentless: the target runs one command that packs a small, explicitly
allow-listed file set (private keys are name-pattern-excluded). Trust model,
limits and the TOFU caveat are spelled out in REMOTE.md.

## Supply chain of this repo itself

- Base `python:3.12-slim`; `pyyaml` pinned by version. **trivy is pinned by
  version and its archive is verified against the release's published
  checksums.txt at build time** — a swapped artifact fails the build loudly.
- CI (see `docs/EXAMPLE-ci.yml`) runs the test suite, a stdlib-only selftest,
  and trivy over this repo's own dependencies on every push and weekly.
- Findings DB/reports live in one named volume (`bastion-data`). Delete the
  volume = wipe its state; nothing else is persisted.
- It's honest about coverage: anything it couldn't check shows up as a
  `scan-gap` finding. A dead scanner exits nonzero (20) — crashes never look
  like clean hosts.

## Threat-model honesty (what this does NOT protect)

- Not a substitute for an IDS/EDR: no runtime monitoring, no logs analysis.
- No web-app scanning, no secrets scanning of your repos.
- Debian/Ubuntu OS CVEs are strong (OSV ecosystem data); RPM distros are
  best-effort (OSV Fedora/Rocky/Alma + offline trivy hints); macOS/Windows/
  appliances: out of scope.
- It cannot know your threat model. A homelab and a payment stack run the
  same scan and should act on it differently.

Found a vulnerability in bastion-open itself? See the private-report route in
SECURITY.md at the repo root.
