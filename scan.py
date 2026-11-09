#!/usr/bin/env python3
"""bastion-open scan entrypoint.
Reads config/config.yaml (inventory of hosts/targets/urls), writes:
  state/last-scan.json   (full findings)
  state/report.md        (human report)
  stdout: one stable digest line + counts (monitor-gate friendly, no timestamps).
Exit code: 0 normally, 10 if critical/high/KEV present (CI can gate on it)."""
import json, os, subprocess, sys, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from bastion_core import scan_host, mark_fixable, probe_urls, kev_set, http_json

CFG = Path(os.environ.get("BASTION_CONFIG", "/app/config/config.yaml"))
if not CFG.exists():  # fresh clone / bare-metal run: fall back to repo-local example
    for alt in (CFG.parent / "config.example.yaml", Path(__file__).parent / "config/config.example.yaml"):
        if alt.exists():
            CFG = alt
            break


def load_cfg():
    try:
        import yaml
        return yaml.safe_load(CFG.read_text()) or {}
    except FileNotFoundError:
        print(f"missing {CFG}; copy config/config.example.yaml", file=sys.stderr); raise SystemExit(2)
    except ImportError:
        cfg = {"targets": [{"host": os.environ.get("BASTION_HOST", "/host")}], "urls": []}
        return cfg


def trivy_target(name, image=None, fs=None):
    if not shutil_which("trivy"):
        return {"target": name, "findings": [], "note": "trivy binary absent; target skipped"}
    cmd = ["trivy", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL,MEDIUM"]
    cmd += (["image", image] if image else ["filesystem", fs])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        j = json.loads(p.stdout or "{}")
    except Exception as e:
        return {"target": name, "findings": [], "note": f"trivy failed: {str(e)[:60]}"}
    out = []
    for r in j.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            out.append({"target": f"{name}/{r.get('Target','')}", "kind": "cve-package",
                        "package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                        "cve": v.get("CVEID"), "fix": v.get("FixedVersion") or "no fix released",
                        "severity": v.get("Severity", "unknown").lower(), "kev": bool(v.get("KEV"))})
    return {"target": name, "findings": out}


def shutil_which(x):
    import shutil
    return shutil.which(x)


def main():
    cfg = load_cfg()
    kev = kev_set()
    findings, meta = [], []
    for t in cfg.get("targets", []):
        if t.get("image") or t.get("fs"):
            meta.append(trivy_target(t.get("name", "target"), t.get("image"), t.get("fs")))
        else:
            h = t.get("host") or "/host"
            if h == "/host" and os.environ.get("BASTION_HOST"):  # bare-metal run override
                h = os.environ["BASTION_HOST"]
            r = scan_host(h)
            if r["error"]:
                findings.append({"target": t.get("name", "host"), "kind": "scan-gap", "severity": "medium",
                                 "package": "", "cve": "", "fix": "", "description": r["error"], "kev": False})
            findings.extend(r["findings"])
            if os.environ.get("BASTION_MARK_FIXABLE") == "1":
                r = mark_fixable(r, t.get("host", "/host"))
            meta.append({"target": t.get("name", "host"), "os": r["os"], "packages": r["packages"]})
    urls = cfg.get("urls", [])
    if urls:
        codes = probe_urls(urls)
        for u, c in codes.items():
            if str(c).startswith(("4", "5")) or c == "000":
                findings.append({"target": "edge", "kind": "exposure", "severity": "medium",
                                 "package": u, "cve": "", "fix": "", "description": f"HTTP {c}", "kev": False})
    for f in findings:
        f.setdefault("kev", False)
        if f.get("cve", "").startswith("CVE-") and f["cve"] in kev:
            f["kev"] = True
    # dedupe + persist
    seen, uniq = set(), []
    for f in findings:
        k = (f["target"], f.get("package"), f.get("cve") or f.get("description"))
        if k not in seen:
            seen.add(k); uniq.append(f)
    State = Path(os.environ.get("BASTION_STATE", "/data")); State.mkdir(exist_ok=True)
    (State / "last-scan.json").write_text(json.dumps({"meta": meta, "findings": uniq}, indent=1))
    write_report(State / "report.md", uniq, meta)
    digest = stable_digest(uniq)
    (State / "digest").write_text(digest)
    c = collections.Counter(f["severity"] for f in uniq)
    kevh = sum(1 for f in uniq if f.get("kev"))
    print(f"BASTION-OPEN {len(uniq)} findings crit={c['critical']} high={c['high']} med={c['medium']} kev={kevh}")
    print(f"digest={digest}")
    # BASTION_EXIT_ON=kev,critical (recommended for CI) | none | high | any
    trig = os.environ.get("BASTION_EXIT_ON", "kev,critical")
    if trig == "none": return 0
    if "any" in trig: return 1
    if "kev" in trig and kevh: return 10
    if "critical" in trig and c["critical"]: return 10
    if "high" in trig and c["high"]: return 10
    return 0


def stable_digest(findings):
    import hashlib
    s = hashlib.sha256("|".join(sorted(
        f"{f['target']}:{f.get('package')}:{f.get('cve')}:{f['severity']}" for f in findings)).encode())
    return s.hexdigest()[:16]


def write_report(path, findings, meta):
    c = collections.Counter(f["severity"] for f in findings)
    lines = ["# bastion-open security report", "",
             f"Findings: CRIT={c['critical']} HIGH={c['high']} MED={c['medium']} LOW={c['low']} "
             f"KEV={sum(1 for f in findings if f.get('kev'))} total={len(findings)}", ""]
    for m in meta:
        lines.append(f" - {m['target']}: {m.get('os','image')} {m.get('packages','')} packages")
    hot = [f for f in findings if f.get("kev") or f["severity"] in ("critical", "high")]
    if hot:
        lines += ["", "## Needs attention"]
        for f in sorted(hot, key=lambda x: ("kev" if x.get("kev") else "", x["severity"])):
            lines.append(f" - {'🚨KEV ' if f.get('kev') else ''}[{f['severity']}] {f['target']} "
                         f"{f.get('package','')} {f.get('installed','')} {f.get('cve','')} -> {f.get('fix','')}")
    lines += ["", "_No fix was applied; this tool is detect-and-report by default. See docs/FIXING.md._"]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
