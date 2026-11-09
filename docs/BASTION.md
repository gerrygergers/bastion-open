# Lineage: bastion -> bastion-open

The original "bastion" is a personal 11-module security suite running on one
homelab server (a GB10 machine + a fleet of VMs, NAS, UniFi gear). It includes
things that only make sense with that estate: ssh inventories with real
hostnames, a UniFi controller integration, a Vikunja ticket spine, Caddy
route probing, and a cron/UI/agent glue layer.

This repo extracts the parts that are universal:
- per-package OS CVE analysis via OSV (with the ecosystem quirks documented in
  `bastion_core.osv_batch` — those were learned expensively)
- CISA KEV overlay
- the chroot-apt fixability model and dry-run abort guard
- report/digest design (stable digests so nightly runs are silence-by-default)

What was left behind, on purpose:
- all ssh targets, hostnames, IPs, credentials (none here; config is the only
  place identity could appear, and it ships empty)
- network-appliance integrations (UniFi API)
- the agent-harness cron gating (this is a normal tool; run it with a normal timer)
