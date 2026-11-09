# The opt-in fixer

By default bastion-open changes nothing. `fix.py` will apply apt security
upgrades when — and only when — **all** of these are true:

1. You run the `fixer` service explicitly: `docker compose --profile fix run fixer`
   (the scanner profile's `/host` is read-only; only the fixer mounts it read-write)
2. `BASTION_FIX=on` **and** `BASTION_FIX_CONFIRM=yes-i-understand` are set (the
   fixer service ships these; running it is the decision)
3. The mount test passes (it writes/deletes a probe file first)

What it then does:
- recomputes the fixable set live from `apt --only-upgrade -s` — a stale report
  can never drive a fix
- **aborts** if apt's plan would REMOVE any package
- upgrades, and writes every action to `/data/journal.jsonl`

What it will never do: install new packages, remove anything, autoremove, edit
config, reboot. (Reboot-required is a finding, not an action.)

## Why so much ceremony?

This code runs as root against your whole filesystem. On the homelab it grew,
that autonomy was the point, and it earned its keep (it repaired a broken dpkg
state on a VM during a fix — a fixer that couldn't react would have just failed).
Published to strangers, "just fix it" is how you get someone's weekend ruined:
their distro, their mirrors, their kernel packages. So: the default is safe, the
capable mode is two deliberate decisions deep. That's the honest trade, and it's
configurable because it's your machine.
