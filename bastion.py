#!/usr/bin/env python3
"""bastion-open — one entrypoint for the whole tool.

  ./bastion.py scan               audit + report (exit 10 on kev/critical)
  ./bastion.py scan --reset       re-baseline silently (day one, or after big churn)
  ./bastion.py status             counts + digest of the last scan
  ./bastion.py report             print state/report.md
  ./bastion.py fix --dry-run      what the policy WOULD apply (changes nothing)
  ./bastion.py fix                real remediation (needs the double env gate)
  ./bastion.py version

Works three ways: inside the container (docker compose run scanner), directly on
a host with python3 (stdlib only; BASTION_HOST=/ ), or via ./install.sh.
"""
import json, os, subprocess, sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
STATE = Path(os.environ.get("BASTION_STATE", HERE / "state"))


def cmd_scan(argv):
    os.environ.setdefault("BASTION_STATE", str(STATE))
    for a in argv:
        if a == "--reset":
            os.environ["BASTION_RESET_BASELINE"] = "1"
    import scan
    return scan.main()


def cmd_status(_):
    try:
        s = json.loads((STATE / "last-scan.json").read_text())
    except Exception:
        print("no scan yet — run: ./bastion.py scan"); return 1
    fs = s.get("findings", [])
    import collections
    c = collections.Counter(f.get("severity", "?") for f in fs)
    kev = sum(1 for f in fs if f.get("kev"))
    gaps = [f for f in fs if f.get("kind") == "scan-gap"]
    print(f"targets: {', '.join(m['target'] for m in s.get('meta', []))}")
    print(f"findings: {len(fs)}  crit={c['critical']} high={c['high']} med={c['medium']} "
          f"low={c['low']} info={c['info']} KEV={kev}")
    if gaps:
        print(f"scan gaps: {len(gaps)} (areas not covered — check the report)")
    try:
        print("digest:", (STATE / "digest").read_text())
    except Exception:
        pass
    return 0


def cmd_report(_):
    try:
        print((STATE / "report.md").read_text())
    except Exception:
        print("no report yet — run: ./bastion.py scan"); return 1
    return 0


def cmd_fix(argv):
    import fix
    return fix.main(argv)


def cmd_version(_):
    from bastion_core import VERSION
    print("bastion-open", VERSION)
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    rest = sys.argv[2:]
    fn = {"scan": cmd_scan, "status": cmd_status, "report": cmd_report,
          "fix": cmd_fix, "version": cmd_version}.get(cmd)
    if not fn:
        print(__doc__); return 2
    return fn(rest)


if __name__ == "__main__":
    raise SystemExit(main())
