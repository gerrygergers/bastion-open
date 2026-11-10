#!/usr/bin/env python3
"""OPT-IN remediation for Debian/Ubuntu hosts. Off unless you make it loud:
  BASTION_FIX=on  AND  BASTION_FIX_CONFIRM=yes-i-understand
and the /host mount must be READ-WRITE (fixer service in compose does that).

Modes:
  python3 fix.py --dry-run   policy decision + apt simulation, NOTHING changes.
                             Works without the rw mount; the best first step.
  python3 fix.py             the real thing, behind the double env gate.

What it does: apt-get --only-upgrade for packages that (a) have open CVEs on
THIS host, (b) apt confirms a candidate exists right now, and (c) policy.py
clears: urgent fixes (KEV / critical+CVSS>=9) apply now, everything else soaks
48h, and packages under a supply-chain incident watch are held for a human.
What it never does: install new packages, remove anything, autoremove, touch
config, reboot. A dry-run abort guard stops any plan that would REMOVE packages.
Every action -> state/journal.jsonl.
Reads state/last-scan.json from a prior scan.py run; the fixable set is
recomputed live so a stale report can never drive a decision."""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from bastion_core import read_dpkg_status, host_os, osv_batch
import policy

STATE = Path(os.environ.get("BASTION_STATE", "/data"))
HOST = os.environ.get("BASTION_HOST", "/host")
PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9+.\-]{1,78}(:[a-z0-9\-]{1,30})?$")  # Debian policy charset


def gate(dry):
    if dry:
        return True
    if os.environ.get("BASTION_FIX") != "on" or os.environ.get("BASTION_FIX_CONFIRM") != "yes-i-understand":
        print("fixer refuses to run: needs BASTION_FIX=on BASTION_FIX_CONFIRM=yes-i-understand "
              "(and a read-write /host mount via the fixer service). Docs: docs/FIXING.md\n"
              "Nothing to lose yet: try `python3 fix.py --dry-run` first.")
        return False
    try:  # verify the mount is actually writable BEFORE apt tries (and half-fails)
        t = Path(HOST) / ".bastion-wtest"
        t.write_text("x"); t.unlink()
    except OSError:
        print(f"fixer refuses to run: {HOST} is mounted read-only; use the fixer service "
              "(docker compose --profile fix run fixer)")
        return False
    return True


def apt(pkgs, simulate=True):
    sfx = ["-s"] if simulate else ["-y"]
    # 'apt-get --only-upgrade X' is NOT a valid invocation (no subcommand: apt
    # errors out and the fixer silently no-ops — verified). The real shape is
    # 'install --only-upgrade', and '--' pins the rest as subjects, not options.
    cmd = ["chroot", HOST, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install",
           "--only-upgrade"] + sfx + ["--"] + pkgs
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    return p.stdout + p.stderr, p.returncode


def apt_update():
    try:
        subprocess.run(["chroot", HOST, "apt-get", "update", "-qq"], capture_output=True, timeout=600)
    except Exception:
        pass  # candidate list may already be fresh; simulation is the authority anyway


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="show the policy decision + what apt WOULD do; change nothing")
    args = ap.parse_args(argv)
    if not gate(args.dry_run):
        return 2
    try:
        scan = json.loads((STATE / "last-scan.json").read_text())
    except Exception:
        print("no state/last-scan.json — run the scanner first"); return 2
    # scope to THIS host only (multi-target scans share one last-scan.json).
    # NO fallback-to-everything: findings about other machines (ssh fleet
    # targets, images, or a planted last-scan.json) must never drive apt here.
    host_name = (Path(HOST).name or "host").lower()
    scoped = [f for f in scan["findings"]
              if str(f.get("target", "")).split("|")[-1].lower() in (host_name, "local-host", "host")]
    if not scoped:
        print("no findings scoped to this host; nothing to do "
              "(run the scanner against this machine first)")
        return 0
    decision = policy.decide(scoped)
    vuln_pkgs = sorted(decision["apply"] & {f["package"] for f in scoped
                                           if f["kind"] == "cve-os" and f.get("package")})
    if decision["deferred"]:
        print(f"policy: {len(decision['deferred'])} package(s) deferred (soak/incident watch); "
              "queue in state/fix-policy.json")
    if not vuln_pkgs:
        print("nothing to fix"); return 0
    apt_update()
    vuln_pkgs = [p for p in vuln_pkgs if PKG_NAME.match(p)]   # argv-safe: no '-option', no paths
    dry, rc = apt(vuln_pkgs, simulate=True)
    if re.search(r"The following packages will be REMOVED", dry, re.I):
        print("ABORT: apt's plan would remove packages. Manual review needed. Dry-run tail:\n", dry[-600:])
        return 3
    upgrade_pkgs = [m.group(1) for m in
                    re.finditer(r"^Inst (\S+)(?::\S+)? \[[^\]]*\] \((\S+)", dry, re.M)]
    if not upgrade_pkgs:
        print("0 packages have an apt candidate right now; findings are upstream-unfixed. Nothing done.")
        return 0
    print(f"{len(upgrade_pkgs)} package(s) policy-cleared with an apt candidate: "
          f"{', '.join(upgrade_pkgs[:12])}{'...' if len(upgrade_pkgs) > 12 else ''}")
    if args.dry_run:
        print("dry-run: nothing applied. Run the fixer service to apply.")
        return 0
    out, arc = apt(upgrade_pkgs, simulate=False)
    ok = arc == 0 and "\nE:" not in out
    STATE.mkdir(parents=True, exist_ok=True)
    jpath = STATE / "journal.jsonl"
    fd = os.open(jpath, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as f:   # O_NOFOLLOW: a planted symlink can't redirect root's audit log
        f.write(json.dumps({"ts": int(time.time()), "action": "apt-only-upgrade", "host": "mounted",
                            "ok": ok, "packages": upgrade_pkgs, "output_tail": out[-300:]}) + "\n")
    print("done, journal at", STATE / "journal.jsonl", "" if ok else "BUT apt errored; see journal")
    if ok:
        policy.note_applied(upgrade_pkgs)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
