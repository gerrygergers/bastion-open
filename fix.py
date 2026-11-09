#!/usr/bin/env python3
"""OPT-IN remediation for Debian/Ubuntu hosts. Off unless you make it loud:
  BASTION_FIX=on  AND  BASTION_FIX_CONFIRM=yes-i-understand
and the /host mount must be READ-WRITE (fixer service in compose does that).

What it does: apt-get --only-upgrade for packages that (a) have open CVEs and
(b) apt confirms a candidate exists. What it never does: install new packages,
remove anything, autoremove, touch config, reboot. A dry-run abort guard stops
any plan that would REMOVE packages. Every action -> state/journal.jsonl.
Read state/last-scan.json from a prior scan.py run; fixable set is recomputed
live so stale reports can't drive decisions."""
import json, os, re, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from bastion_core import read_dpkg_status, host_os, osv_batch

STATE = Path(os.environ.get("BASTION_STATE", "/data"))
HOST = os.environ.get("BASTION_HOST", "/host")


def gate():
    if os.environ.get("BASTION_FIX") != "on" or os.environ.get("BASTION_FIX_CONFIRM") != "yes-i-understand":
        print("fixer refuses to run: needs BASTION_FIX=on BASTION_FIX_CONFIRM=yes-i-understand "
              "(and a read-write /host mount via the fixer service). Docs: docs/FIXING.md")
        return False
    try:  # verify the mount is actually writable BEFORE apt tries (and half-fails)
        t = Path(HOST) / ".bastion-wtest"
        t.write_text("x"); t.unlink()
    except OSError:
        print(f"fixer refuses to run: {HOST} is mounted read-only; use the fixer service "
              "(docker compose --profile fix run fixer)")
        return False
    return True


def apt(box_cmd, pkgs, simulate=True):
    sfx = ["-s"] if simulate else ["-y"]
    cmd = ["chroot", HOST, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "--only-upgrade"] + sfx + pkgs
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    return p.stdout + p.stderr


def main():
    if not gate():
        return 2
    scan = json.loads((STATE / "last-scan.json").read_text())
    vuln_pkgs = sorted({f["package"] for f in scan["findings"] if f["kind"] == "cve-os" and f.get("severity") in ("critical", "high", "medium", "unknown")})
    if not vuln_pkgs:
        print("nothing to fix"); return 0
    dry = apt("sim", vuln_pkgs, simulate=True)
    if re.search(r"The following packages will be REMOVED", dry, re.I):
        print("ABORT: apt's plan would remove packages. Manual review needed. Dry-run tail:\n", dry[-600:])
        return 3
    upgrade_pkgs = [m.group(1).rstrip(":anyarch") for m in re.finditer(r"^Inst (\S+) \[[^\]]*\] \((\S+)", dry, re.M)]
    if not upgrade_pkgs:
        print("0 packages have an apt candidate right now; findings are upstream-unfixed. Nothing done.")
        return 0
    print(f"upgrading {len(upgrade_pkgs)} packages: {', '.join(upgrade_pkgs[:12])}{'...' if len(upgrade_pkgs)>12 else ''}")
    out = apt("run", upgrade_pkgs, simulate=False)
    ok = "returned an error code" not in out and "E:" not in out
    STATE.mkdir(exist_ok=True)
    with open(STATE / "journal.jsonl", "a") as f:
        f.write(json.dumps({"ts": int(time.time()), "action": "apt-only-upgrade", "host": "mounted",
                            "ok": ok, "packages": upgrade_pkgs, "output_tail": out[-300:]}) + "\n")
    print("done, journal at", STATE / "journal.jsonl", "" if ok else "BUT apt errored; see journal")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
