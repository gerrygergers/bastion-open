# Security model — quick index

Full threat model, privilege shape, and honest coverage limits:
**[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)**. Read it before running
the fixer or pointing the scanner at machines you didn't build.

## Reporting a vulnerability

If you believe you've found a security issue in bastion-open, please report it
privately via GitHub → Security tab → "Report a vulnerability"
(https://github.com/gerrygergers/bastion-open/security/advisories/new).

- What: anything that lets the tool mutate a system outside its documented
  gates, exfiltrate inventory data, or bypass the fix policy.
- Timeline: acknowledged within 7 days, fixed or disputed within 30.
- Please don't open a public issue first. Credit on request.

## Hardening the fixer before you turn it on

`docs/FIXING.md` covers the gates and policy; in short: urgent (KEV or
critical+CVSS≥9) applies immediately, everything else soaks 48h for
supply-chain safety, and packages you list in `config/incidents.yaml` are held
for human review forever. Dry-run is always available and always safe:
`fix.py --dry-run`.
