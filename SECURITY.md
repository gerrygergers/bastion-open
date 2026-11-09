# Security model (read me first)

- **What the scanner does:** reads `/etc/os-release`, `/var/lib/dpkg/status`,
  `/proc/net/tcp*`, `/var/run/reboot-required` on the mounted host. Read-only
  file access, outbound HTTPS to api.osv.dev, cisa.gov, and your configured
  URLs. No credentials stored or required.
- **Why mount `/` at all, if only a few paths are read:** simplicity. If you'd
  rather restrict it, mount just those paths (`-v /etc/os-release:/host/etc/os-release:ro`
  etc) and it degrades gracefully with a scan-gap finding.
- **The fixer is different:** `fix.py` needs a read-WRITE host mount and runs
  apt inside `chroot`. That's why it's behind a compose profile, two env gates,
  a live dry-run guard, and a journal. Treat it like the tool that edits your
  system, because it is.
- **Supply chain:** the image is `python:3.12-slim` + trivy (pinned by version,
  downloaded over HTTPS) + pyyaml. `docker build --no-cache` to reproduce; the
  trivy version lives in one ARG.
- **Data:** everything stays in the `bastion-data` volume. Reports contain
  package names and CVE IDs — ordinary to publish, but your call.
