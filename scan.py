#!/usr/bin/env python3
"""bastion-open scan entrypoint.
Reads config/config.yaml (targets, urls, fleet, alerting), scans, and writes:
  state/last-scan.json    full findings
  state/baseline.json     first-seen tracking (cold start is a census, not an alarm)
  state/report.md         human report
  stdout: one stable digest line + counts (deterministic, no timestamps)
Exit codes:
  0  ok / nothing crossing BASTION_EXIT_ON (default kev,critical)
  2  config error
  10 finding(s) matching BASTION_EXIT_ON (CI gate)
  20 internal scan failure (a dead scanner must never look like a clean host)
"""
import hashlib, json, os, subprocess, sys, time, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from bastion_core import (VERSION, scan_host, mark_fixable, probe_urls, kev_set,
                          pack_inventory, unpack_inventory, SAFE_NAME)

CFG = Path(os.environ.get("BASTION_CONFIG", "/app/config/config.yaml"))
try:
    _have_cfg = CFG.exists()
except PermissionError:
    _have_cfg = True     # unreadable dir (caps dropped): treat default as present, fail in load_cfg
if not _have_cfg:        # fresh clone / bare-metal run: fall back to repo-local example
    for alt in (CFG.parent / "config.example.yaml", Path(__file__).parent / "config/config.example.yaml"):
        try:
            if alt.exists():
                CFG = alt
                break
        except PermissionError:
            continue


def load_cfg():
    try:
        raw = CFG.read_text()
    except FileNotFoundError:
        print(f"missing {CFG}; copy config/config.example.yaml", file=sys.stderr)
        raise SystemExit(2)
    try:
        import yaml
        return yaml.safe_load(raw) or {}
    except ImportError:
        pass
    # No pyyaml (e.g. running under the python:slim image without it, or the
    # no-pip fleet path on a remote box): accept a JSON file — JSON is YAML, and
    # our example config ships a .json twin for exactly this case.
    try:
        return json.loads(raw)
    except Exception as e:
        print(f"config unparseable without pyyaml ({e}); install pyyaml or use JSON syntax", file=sys.stderr)
        raise SystemExit(2)


SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
       "-o", "ServerAliveCountMax=3", "-o", "StrictHostKeyChecking=accept-new"]


def scan_ssh_target(name, spec):
    """Collect a read-only inventory from a remote Linux box over ssh and scan it
    locally. Two transports: (1) stream our own core module in and run
    pack_inventory remotely (needs python3 on the target); (2) fallback plain
    tar of the same paths. Nothing is installed or written remotely beyond a
    temp file that the same command removes."""
    host = spec.get("host") or name
    user = spec.get("user", "")
    dest = (user + "@" if user else "") + host
    port = ["-p", str(spec["port"])] if spec.get("port") else []
    work = Path(os.environ.get("BASTION_STATE", "/data")) / "fleet" / re_sub(name)
    work.mkdir(parents=True, exist_ok=True)
    tar = work / "inv.tgz"
    err_tail = ""
    core_src = (Path(__file__).parent / "bastion_core.py").read_bytes()
    drive = ("import sys; exec(sys.stdin.buffer.read().decode('utf-8',"
             "'replace')); pack_inventory('/', '/tmp/bastion-inv.tgz')")
    p = subprocess.run(SSH + port + [dest, f"python3 -c {shlex_q(drive)}"],
                       input=core_src, capture_output=True, timeout=60)
    if p.returncode == 0:
        p2 = subprocess.run(SSH + port + [dest,
                            "base64 /tmp/bastion-inv.tgz; rm -f /tmp/bastion-inv.tgz"],
                            capture_output=True, text=True, timeout=120)
        if p2.returncode == 0 and p2.stdout.strip():
            import base64
            try:
                tar.write_bytes(base64.b64decode(p2.stdout))
            except Exception as e:
                err_tail = f"b64 decode: {e}"
    else:
        err_tail = (p.stderr or b"")[-200:].decode(errors="replace")
    if not tar.exists():  # fallback: plain tar, no python needed on the target
        keep = ("etc/os-release etc/ssh/sshd_config etc/ssh/sshd_config.d etc/passwd etc/group "
                "etc/shadow etc/sudoers etc/sudoers.d etc/cron.d proc/net/tcp proc/net/tcp6 "
                "var/lib/dpkg/status var/run/reboot-required")
        p = subprocess.run(SSH + port + [dest,
                           f"tar -cz --exclude='*key*' -f - {keep} 2>/dev/null"],
                           capture_output=True, timeout=120)
        if p.returncode in (0, 1) and p.stdout:   # tar rc=1 = 'some files vanished', fine
            tar.write_bytes(p.stdout)
    if not tar.exists():
        return {"target": name, "findings": [ssh_gap(name, err_tail)],
                "meta": {"target": name, "os": "ssh-fail"}}
    try:
        root = unpack_inventory(tar, work / "root")
    except Exception as e:
        return {"target": name, "findings": [ssh_gap(name, f"inventory unpack failed: {e}")],
                "meta": {"target": name, "os": "ssh-fail"}}
    r = scan_host(str(root), do_configbench=True)
    r["findings"] = [dict(f, target=name) for f in r["findings"]]
    return {"target": name, "findings": r["findings"],
            "meta": {"target": name, "os": r["os"], "packages": r["packages"], "via": "ssh"},
            "error": r["error"]}


def re_sub(name):
    import re
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def shlex_q(s):
    import shlex
    return shlex.quote(s)


def ssh_gap(name, err_tail):
    return {"target": name, "kind": "scan-gap", "severity": "medium", "package": "",
            "cve": "", "fix": "check ssh reachability/keys", "kev": False,
            "description": f"ssh inventory failed for {name}: {str(err_tail)[-120:]}"}


def trivy_target(name, image=None, fs=None):
    if not shutil_which("trivy"):
        return {"target": name, "findings": [],
                "note": "trivy binary absent; target skipped",
                "gap": {"target": name, "kind": "scan-gap", "severity": "medium", "package": "",
                        "cve": "", "fix": "include trivy in the image or run the full container",
                        "description": f"trivy absent; target '{name}' NOT scanned", "kev": False}}
    cmd = ["trivy", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL,MEDIUM",
           "--security-checks", "vuln", "--db-repository", "public.ecr.aws/aquasecurity/trivy-db"]
    cmd += (["image", image] if image else ["filesystem", fs])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        j = json.loads(p.stdout or "{}")
    except Exception as e:
        return {"target": name, "findings": [], "note": f"trivy failed: {str(e)[:60]}",
                "gap": {"target": name, "kind": "scan-gap", "severity": "medium", "package": "",
                        "cve": "", "fix": "", "description": f"trivy failed on {name}: {str(e)[:80]}", "kev": False}}
    out = []
    for r in j.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            out.append({"target": f"{name}/{r.get('Target','')}", "kind": "cve-package",
                        "package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                        "cve": v.get("CVEID"), "fix": v.get("FixedVersion") or "no fix released",
                        "severity": v.get("Severity", "unknown").lower(), "kev": bool(v.get("KEV")),
                        "cvss": 0.0, "pub": v.get("PublishedDate", "")})
    return {"target": name, "findings": out}


def shutil_which(x):
    import shutil
    return shutil.which(x)


# --------------------------------------------------------------- baseline diff

def diff_baseline(findings, state):
    """First run (or --reset-baseline): record everything silently. Afterwards a
    finding is NEW if its watch_key was never seen open. Returns (new, resolved)."""
    bpath = state / "baseline.json"
    try:
        base = json.loads(bpath.read_text())
    except Exception:
        base = None
    keys = {watch_key(f) for f in findings}
    if base is None or os.environ.get("BASTION_RESET_BASELINE") == "1":
        # cold start OR explicit reset: record silently — everything is "known"
        # from here; nothing alerts. (Day one is a census, not an alarm.)
        bpath.write_text(json.dumps({"version": 1, "seen": sorted(keys)}))
        return set(), set()
    prev = set(base.get("seen", []))
    new = keys - prev
    resolved = prev - keys
    bpath.write_text(json.dumps({"version": 1, "seen": sorted(keys)}))
    return new, resolved


def watch_key(f):
    return f"{f['target']}|{f.get('kind')}|{f.get('package','')}|{f.get('cve') or f.get('check_id') or f.get('description','')}"


# ------------------------------------------------------------------- alerting

def send_alerts(cfg, new_uniq, kev_hits):
    """Webhooks: ntfy / generic JSON. Failures are printed, never crash the scan.
    Returns list of delivered channel names."""
    hooks = cfg.get("alert", {}).get("webhooks", [])
    if not hooks:
        return []
    hot = [f for f in new_uniq if f["severity"] in ("critical", "high")] + \
          [f for f in kev_hits if f not in new_uniq]
    if not hot:
        return []  # silence-by-default; digest lives in the report
    sev = "CRITICAL" if any(f["severity"] == "critical" for f in hot) else "HIGH"
    top = ", ".join(sorted({f.get("package") or f.get("check_id") or f.get("description", "?")[:40]
                            for f in hot}))[:400]
    title = f"[bastion] {sev}: {len(hot)} new finding(s)"
    body = f"{title}\n{top}\nSee report.md for detail."
    import urllib.request
    delivered = []
    for h in hooks:
        url = h.get("ntfy") or h.get("url")
        if not url or not SAFE_NAME.match(url):
            print(f"alert webhook skipped (bad url): {str(url)[:80]}", file=sys.stderr)
            continue
        try:
            if h.get("ntfy"):
                req = urllib.request.Request(url, data=body.encode(), method="POST",
                                            headers={"Title": title, "Priority": "high",
                                                     "Tags": "rotating_light", "User-Agent": "bastion-open"})
            else:  # generic JSON (Slack-compatible {"text":...})
                payload = json.dumps(h.get("payload", {"text": body})).encode()
                req = urllib.request.Request(url, data=payload, method="POST",
                                             headers={"Content-Type": "application/json",
                                                      "User-Agent": "bastion-open"})
                if h.get("header"):
                    for k, v in h["header"].items():
                        req.add_header(k, str(v))
            urllib.request.urlopen(req, timeout=15).read()
            delivered.append(url.split("//", 1)[-1].split("/")[0])
        except Exception as e:
            print(f"alert webhook failed: {str(e)[:100]}", file=sys.stderr)
    return delivered


# ----------------------------------------------------------------------- main

def main():
    cfg = load_cfg()
    kev = kev_set()
    findings, meta = [], []
    targets = cfg.get("targets") or [{"host": os.environ.get("BASTION_HOST", "/host"), "name": "local-host"}]
    for t in targets:
        try:
            if t.get("ssh"):
                r = scan_ssh_target(t.get("name", t["ssh"]), {"host": t["ssh"], "user": t.get("user", "")})
                findings.extend(r["findings"])
                meta.append(r["meta"])
                continue
            if t.get("image") or t.get("fs"):
                m = trivy_target(t.get("name", "target"), t.get("image"), t.get("fs"))
                if m.get("gap"):
                    findings.append(m["gap"])
                meta.append({"target": t.get("name", "image"), "os": "image", "packages": ""})
                findings.extend(m["findings"])
                continue
            h = t.get("host") or "/host"
            if h == "/host" and os.environ.get("BASTION_HOST"):
                h = os.environ["BASTION_HOST"]
            r = scan_host(h, do_configbench=cfg.get("configbench", True))
            if r["error"]:
                findings.append({"target": t.get("name", "host"), "kind": "scan-gap", "severity": "medium",
                                 "package": "", "cve": "", "fix": "", "description": r["error"], "kev": False})
            findings.extend(r["findings"])
            if os.environ.get("BASTION_MARK_FIXABLE") == "1":
                r = mark_fixable(r, h)
            meta.append({"target": t.get("name", "host"), "os": r["os"], "packages": r["packages"]})
        except Exception as e:
            print(f"target failed ({t}): {str(e)[:120]}", file=sys.stderr)
            findings.append({"target": t.get("name", "?"), "kind": "scan-gap", "severity": "high",
                             "package": "", "cve": "", "fix": "", "kev": False,
                             "description": f"scan crashed for this target: {str(e)[:120]}"})
    urls = cfg.get("urls", [])
    if urls:
        for u, rec in probe_urls(urls).items():
            c = str(rec["code"])
            if c.startswith(("4", "5")) or c == "000":
                findings.append({"target": "edge", "kind": "exposure", "severity": "medium",
                                 "package": u, "cve": "", "fix": "", "kev": False,
                                 "description": f"HTTP {c}"})
            exp = rec.get("tls_expiry_days")
            if exp is not None and exp < 14:
                findings.append({"target": "edge", "kind": "exposure",
                                 "severity": "critical" if exp < 0 else "medium",
                                 "package": u, "cve": "", "kev": False,
                                 "fix": "renew certificate",
                                 "description": f"TLS cert expires in {exp}d"})
    for f in findings:
        f.setdefault("kev", False)
        if f.get("cve", "").startswith("CVE-") and f["cve"] in kev:
            f["kev"] = True
    # dedupe + persist
    seen, uniq = set(), []
    for f in findings:
        k = watch_key(f)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    State = Path(os.environ.get("BASTION_STATE", "/data"))
    try:
        State.mkdir(parents=True, exist_ok=True)
        probe = State / ".wtest"
        probe.write_text("x"); probe.unlink()
    except PermissionError:
        print(f"STATE dir {State} is not writable. If this is the bastion-data "
              "volume from a v0.1 image, one-time fix:\n"
              "  docker run --rm -v bastion-data:/data busybox chmod 1777 /data",
              file=sys.stderr)
        return 20
    new_keys, resolved_keys = diff_baseline(uniq, State)
    for f in uniq:
        f["first_seen_new"] = watch_key(f) in new_keys
    (State / "last-scan.json").write_text(json.dumps({"version": 1, "meta": meta, "findings": uniq}, indent=1))
    write_report(State / "report.md", uniq, meta, new_keys)
    digest = stable_digest(uniq)
    (State / "digest").write_text(digest)
    # alert = NEW crit/high or NEW KEV only; 'new' comes from the baseline, so a
    # given finding pings at most once in the tool's lifetime. No re-ping spam.
    if cfg.get("alert"):
        send_alerts(cfg, [f for f in uniq if f["first_seen_new"]
                          and (f["severity"] in ("critical", "high") or f.get("kev"))], [])
    c = collections.Counter(f["severity"] for f in uniq)
    kevh = sum(1 for f in uniq if f.get("kev"))
    hot = sum(1 for f in uniq if f["first_seen_new"] and f["severity"] in ("critical", "high"))
    print(f"BASTION-OPEN {VERSION} {len(uniq)} findings crit={c['critical']} high={c['high']} "
          f"med={c['medium']} kev={kevh} new_crit_high={hot} resolved_since_last={len(resolved_keys)}")
    print(f"digest={digest}")
    trig = os.environ.get("BASTION_EXIT_ON", "kev,critical")
    if trig == "none":
        return 0
    if "any" in trig:
        return 1
    if "kev" in trig and kevh:
        return 10
    if "critical" in trig and c["critical"]:
        return 10
    if "high" in trig and c["high"]:
        return 10
    return 0


def stable_digest(findings):
    s = hashlib.sha256("|".join(sorted(
        f"{f['target']}:{f.get('package')}:{f.get('cve') or f.get('check_id') or f.get('description','')}:{f['severity']}"
        for f in findings)).encode())
    return s.hexdigest()[:16]


def write_report(path, findings, meta, new_keys=None):
    c = collections.Counter(f["severity"] for f in findings)
    new_keys = new_keys or set()
    lines = ["# bastion-open security report", "",
             f"Findings: CRIT={c['critical']} HIGH={c['high']} MED={c['medium']} LOW={c['low']} "
             f"KEV={sum(1 for f in findings if f.get('kev'))} total={len(findings)}", ""]
    for m in meta:
        lines.append(f" - {m['target']}: {m.get('os','image')} {m.get('packages','')} packages")
    gaps = [f for f in findings if f.get("kind") == "scan-gap"]
    if gaps:
        lines += ["", "## Scan gaps (areas NOT covered — read these first)"]
        for f in gaps:
            lines.append(f" - [{f['severity']}] {f['target']}: {f['description']}")
    kev = [f for f in findings if f.get("kev")]
    if kev:
        lines += ["", "## Known exploited (CISA KEV)"]
        for f in sorted(kev, key=lambda x: x["target"]):
            lines.append(f" - {f['target']} {f.get('package','')} {f.get('cve','')} "
                         f"[{f['severity']}] -> {f.get('fix','')}")
    hot = [f for f in findings if f["severity"] in ("critical", "high")]
    if hot:
        lines += ["", "## Needs attention (NEW marked *)"]
        for f in sorted(hot, key=lambda x: (x["severity"] != "critical", x["target"])):
            star = "*" if watch_key(f) in new_keys else " "
            lines.append(f" -{star}[{f['severity']}] {f['target']} "
                         f"{f.get('package') or f.get('check_id') or ''} {f.get('installed','')} "
                         f"{f.get('cve','')} {f.get('description','')} -> {f.get('fix','')}")
    cfgf = [f for f in findings if f.get("kind") == "config-check"]
    if cfgf:
        lines += ["", "## Configuration checks"]
        for f in sorted(cfgf, key=lambda x: x["severity"] != "critical"):
            lines.append(f" - [{f['severity']}] {f['target']} {f['check_id']}: {f['description']} -> {f['fix']}")
    try:  # surface the fix-policy queue (soaking / incident-held) if a fixer has run here
        pol = json.loads((path.parent / "fix-policy.json").read_text())
        pend = list(pol.get("pending", {}).values())
        if pend:
            lines += ["", f"## Fix policy queue ({len(pend)} deferred)"]
            for p in sorted(pend, key=lambda x: x.get("reason", ""))[:15]:
                lines.append(f" - {p['pkg']} [{p.get('severity','?')}] {p['reason']}")
    except Exception:
        pass
    lines += ["", "_No fix was applied; this tool is detect-and-report by default. See docs/FIXING.md._"]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"bastion-open scan failed: {e}", file=sys.stderr)
        raise SystemExit(20)
