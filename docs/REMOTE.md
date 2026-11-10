# Scanning remote machines (agentless over ssh)

bastion-open can audit other Linux boxes **without installing anything on
them**. It opens a normal ssh session, streams a small read-only inventory
(your own machine's copy of `bastion_core.py`, ~28 KB), packs the handful of
security-relevant files, and analyzes everything locally.

## Setup

1. Key-based ssh auth from the machine running bastion-open to the target.
   With the container fleet service, `~/.ssh` (keys + known_hosts) is mounted
   read-only, so the *host user's* ssh config applies.
2. Add the target to `config/config.yaml`:

```yaml
targets:
  - name: web01
    ssh: 10.0.0.21
    user: gerry          # optional; ssh default otherwise
```

3. `docker compose run --rm fleet` (or the same scanner with this config).

## What crosses the wire

`/etc/os-release`, sshd config (+ drop-ins), passwd/group/shadow, sudoers
(+ drop-ins), cron.d, `/proc/net/tcp{,6}`, dpkg status, reboot flag.
**Never** private keys (name-pattern excluded on both transports). The target
runs no persistent code; worst case a temp file in `/tmp` that the same
connection deletes. If python3 is missing on the target it falls back to
plain `tar` of the same paths.

## What you get vs a mounted-host scan

Same CVE analysis (OSV + KEV), same config benchmark. Two gaps, both flagged
as `scan-gap` findings rather than silently clean:

- listeners come from the target's real `/proc/net` (accurate — better than
  the mount case on weird namespaces)
- package DBs beyond dpkg need the python3 transport (rpm parse rides in it)

## Trust model

- The scan machine needs ssh keys = the security boundary. Guard the machine
  running bastion-open like a jump host.
- known_hosts TOFU (`accept-new`): first connect trusts whatever answers. If
  that matters to you, seed known_hosts before the first run — the tool never
  prints key material, and a changed host key makes ssh (and this scan) fail.
- Target-side privilege: whatever the ssh user can read. Run the scanner as a
  user who can read `/etc/shadow` on the target for full benchmark coverage;
  otherwise those checks report scan-gaps, not passes.

## Non-Linux / appliances

Firewalls, NAS boxes, switches: out of scope for OS CVEs. Point `urls:`
probes at their admin panels if you want degradation detection, and keep
firmware updates on their vendor's schedule.
