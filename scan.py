#!/usr/bin/env python3
"""bastion-open scan entrypoint.
Reads config/config.yaml (targets, urls, fleet, alerting), scans, and writes:
  state/last-scan.json    full findings
  state/baseline.json     ever-seen tracking (cold start is a census, not an alarm)
  state/report.md         human report
All state writes go through atomic replace (never in-place): the state dir may
be shared/older-content; a root in-place write follows a planted symlink.
Exit codes:
  0  ok / nothing crossing BASTION_EXIT_ON (default kev,critical)
  2  config error
  10 finding(s) matching BASTION_EXIT_ON (CI gate)
  20 internal scan failure (a dead scanner must never look like a clean host)
"""
import hashlib, json, os, re, subprocess, sys, time, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from bastion_core import (VERSION, scan_host, mark_fixable, probe_urls, kev_set,
                          pack_inventory, unpack_inventory, SAFE_NAME, cache_put)

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
        try:
            return yaml.safe_load(raw) or {}
        except yaml.YAMLError as e:      # a broken config is a config error (2),
            print(f"config unparseable: {str(e).splitlines()[0][:160]}", file=sys.stderr)
            raise SystemExit(2)         # not an internal failure (20)
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

# ssh destination is argv, not shell — but a value that STARTS with '-' or
# carries option syntax would be parsed by ssh as an OPTION (e.g.
# -oProxyCommand=... = remote code execution on the scanner itself). Pin the
# alphabet; host aliases from ~/.ssh/config are the only 'odd' thing allowed.
SSH_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,253}$")
SSH_USER = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def scan_ssh_target(name, spec):
    """Collect a read-only inventory from a remote Linux box over ssh and scan it
    locally. Two transports: (1) stream our own core module in and run
    pack_inventory remotely (needs python3 on the target); (2) fallback plain
    tar of the same paths. Nothing is installed remotely; the temp file is a
    private name the same command creates (O_EXCL) and removes.
    A remote temp path under /tmp owned by a hostile user is why we delete any
    prior local copy BEFORE collecting: stale inventory must never pass as fresh."""
    host = spec.get("host") or name
    user = spec.get("user", "")
    if not SSH_HOST.match(str(host)) or (user and not SSH_USER.match(str(user))):
        return {"target": name, "findings": [ssh_gap(name, "rejected ssh host/user syntax")],
                "meta": {"target": name, "os": "ssh-fail"}}
    dest = (user + "@" if user else "") + host
    port = ["-p", str(int(spec["port"]))] if spec.get("port") else []
    work = Path(os.environ.get("BASTION_STATE", "/data")) / "fleet" / safe_name(name)
    work.mkdir(parents=True, exist_ok=True)
    tar = work / "inv.tgz"
    err_tail = ""
    try:
        tar.unlink()                     # stale inventory is never 'fresh' (F11)
    except FileNotFoundError:
        pass
    core_src = (Path(__file__).parent / "bastion_core.py").read_bytes()
    # unique-ish remote temp: pid+time; set -C (O_EXCL) so a planted symlink at
    # the name makes creation FAIL rather than truncate somebody's file.
    rtmp = f"/tmp/.bastion-inv.{int(time.time())}-{os.getpid()}.tgz"
    drive = ("import sys; exec(sys.stdin.buffer.read().decode('utf-8',"
             "'replace')); pack_inventory('/', %r)" % rtmp)
    p = subprocess.run(SSH + port + [dest, f"set -C 2>/dev/null || true; python3 -c {shlex_q(drive)}"],
                       input=core_src, capture_output=True, timeout=60)
    if p.returncode == 0:
        p2 = subprocess.run(SSH + port + [dest, f"base64 {shlex_q(rtmp)}; rm -f {shlex_q(rtmp)}"],
                            capture_output=True, text=True, timeout=120)
        if p2.returncode == 0 and p2.stdout.strip():
            import base64
            try:
                tmp = tar.with_name(tar.name + f".tmp.{os.getpid()}")
                tmp.write_bytes(base64.b64decode(p2.stdout))
                os.replace(tmp, tar)
            except Exception as e:
                err_tail = f"b64 decode/write: {e}"
    else:
        err_tail = (p.stderr or b"")[-200:].decode(errors="replace")
    if not tar.exists():  # fallback: plain tar, no python needed on the target.
        # --transform prefixes members with host/ so unpack_inventory finds them;
        # GNU tar exists on every Linux we target; targets without python3 but
        # with BSD tar would land members unprefixed (scan gap, not clean).
        keep = ("etc/os-release etc/ssh/sshd_config etc/ssh/sshd_config.d etc/passwd etc/group "
                "etc/shadow etc/sudoers etc/sudoers.d etc/cron.d proc/net/tcp proc/net/tcp6 "
                "var/lib/dpkg/status var/run/reboot-required")
        p = subprocess.run(SSH + port + [dest,
                           f"tar -cz --exclude='*key*' --transform 's,^,host/,' -f - {keep} 2>/dev/null"],
                           capture_output=True, timeout=120)
        if p.returncode in (0, 1) and p.stdout:   # tar rc=1 = 'some files vanished', fine
            tmp = tar.with_name(tar.name + f".tmp.{os.getpid()}")
            tmp.write_bytes(p.stdout)
            os.replace(tmp, tar)
    if not tar.exists():
        return {"target": name, "findings": [ssh_gap(name, err_tail)],
                "meta": {"target": name, "os": "ssh-fail"}}
    try:
        root = unpack_inventory(tar, work / "root")
    except Exception as e:
        return {"target": name, "findings": [ssh_gap(name, f"inventory unpack failed: {e}")],
                "meta": {"target": name, "os": "ssh-fail"}}
    r = scan_host(str(root), do_configbench=True)
    findings = [dict(f, target=name) for f in r["findings"]]
    if r.get("error"):   # remote package-db/OSV problems must surface (F10),
        findings.append({"target": name, "kind": "scan-gap", "severity": "medium",  # same as local
                         "package": "", "cve": "", "fix": "", "kev": False,
                         "description": str(r["error"])[:200]})
    try:
        tar.unlink()                     # shadow hashes need not linger (S6)
    except OSError:
        pass
    return {"target": name, "findings": findings,
            "meta": {"target": name, "os": r["os"], "packages": r["packages"], "via": "ssh"}}


def safe_name(name):
    # collapse to [A-Za-z0-9_.-]; a name that does that maps to itself, and
    # anything starting with . or .. gets a prefix so STATE/fleet/.. can't be
    # STATE itself (S7).
    s = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))[:64]
    while s.startswith("."):
        s = "_" + s
    return s or "target"


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
    env = dict(os.environ, HOME="/tmp")   # read-only rootfs: trivy db cache must land in tmpfs
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=env)
    except Exception as e:
        p = None
        err = str(e)[:80]
    if p is None or p.returncode != 0:
        err = (err if p is None else f"trivy rc={p.returncode}: {(p.stderr or '')[-120:]}")[:120]
        return {"target": name, "findings": [], "note": f"trivy failed: {err}",
                "gap": {"target": name, "kind": "scan-gap", "severity": "medium", "package": "",
                        "cve": "", "fix": "", "description": f"trivy FAILED on {name} (not a clean "
                        f"result): {err}", "kev": False}}
    try:
        j = json.loads(p.stdout or "{}")
    except Exception as e:
        return {"target": name, "findings": [],
                "gap": {"target": name, "kind": "scan-gap", "severity": "medium", "package": "",
                        "cve": "", "fix": "", "description": f"trivy output unparsable for {name}: {e}", "kev": False}}
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
    finding is NEW if its watch_key was never seen open. Returns (new, resolved).
    `ever` is permanent: a finding that resolved and came BACK is not 'new'
    again — webhooks ping each key at most once in the tool's lifetime (F18)."""
    bpath = state / "baseline.json"
    try:
        base = json.loads(bpath.read_text())
        if base.get("version") != 1:
            base = None
    except Exception:
        base = None
    keys = {watch_key(f) for f in findings}
    if base is None or os.environ.get("BASTION_RESET_BASELINE") == "1":
        cache_put(bpath, {"version": 1, "seen": sorted(keys), "ever": sorted(keys)})
        return set(), set()
    prev = set(base.get("seen", []))
    ever = set(base.get("ever", prev)) | prev
    new = (keys - prev) - ever
    resolved = prev - keys
    cache_put(bpath, {"version": 1, "seen": sorted(keys), "ever": sorted(ever | keys)})
    return new, resolved


def watch_key(f):
    kind = f.get("kind")
    if kind == "config-check":
        # PERM-01 fires on five dirs; keying on check_id alone dedupe-eats four
        # of them and 'resolved' lies. Include the per-instance suffix.
        return (f"{f['target']}|{kind}|{f.get('check_id','')}|"
                f"{f.get('key_suffix', f.get('description',''))}")
    return f"{f['target']}|{kind}|{f.get('package','')}|{f.get('cve') or f.get('check_id') or f.get('description','')}"


# ------------------------------------------------------------------- alerting

def send_alerts(cfg, new_uniq, kev_hits):
    """Webhooks: ntfy / generic JSON. Failures are printed, never crash the scan.
    Returns list of delivered channel names."""
    hooks = cfg.get("alert", {}).get("webhooks", [])
    if not hooks:
        return []
    # the documented contract is NEW crit/high OR NEW KEV — a medium that turns
    # out to be exploited in the wild is exactly the finding that must ping (F20)
    hot = [f for f in new_uniq if f["severity"] in ("critical", "high") or f.get("kev")] + \
          [f for f in kev_hits if f not in new_uniq]
    if not hot:
        return []  # silence-by-default; digest lives in the report
    sev = "CRITICAL" if any(f["severity"] == "critical" for f in hot) else \
          ("KEV" if any(f.get("kev") for f in hot) else "HIGH")
    top = ", ".join(sorted({f.get("package") or f.get("check_id") or f.get("description", "?")[:40]
                            for f in hot}))[:400]
    title = f"[bastion] {sev}: {len(hot)} new finding(s)"
    body = f"{title}\n{top}\nSee report.md for detail."
    import urllib.request
    delivered = []
    for h in hooks:
        url = h.get("ntfy") or h.get("url")
        if not url or not SAFE_NAME.match(url) or \
           urllib.parse.urlparse(url).scheme not in ("https", "http"):
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
    kev, kev_note = kev_set()
    findings, meta = [], []
    targets = cfg.get("targets") or [{"host": os.environ.get("BASTION_HOST", "/host"), "name": "local-host"}]
    for t in targets:
        try:
            if t.get("ssh"):
                r = scan_ssh_target(t.get("name", t["ssh"]), {"host": t["ssh"],
                                                              "user": t.get("user", ""),
                                                              "port": t.get("port")})
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
            if exp is None and u.startswith("https://"):
                findings.append({"target": "edge", "kind": "scan-gap", "severity": "low",
                                 "package": u, "cve": "", "fix": "", "kev": False,
                                 "description": "TLS expiry not readable (openssl s_client failed)"})
            elif exp is not None and exp < 14:
                findings.append({"target": "edge", "kind": "exposure",
                                 "severity": "critical" if exp < 0 else "medium",
                                 "package": u, "cve": "", "kev": False,
                                 "fix": "renew certificate",
                                 "description": f"TLS cert expires in {exp}d"})
    if kev_note:   # a dead KEV feed is a scan gap, not a clean run (S4)
        findings.append({"target": "kev-feed", "kind": "scan-gap", "severity": "medium",
                         "package": "", "cve": "", "fix": "check outbound HTTPS to cisa.gov",
                         "description": kev_note, "kev": False})
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
        os.chmod(State, 0o750)     # default-deny where root's reports live;
    except OSError:
        pass                       # a shared/pre-existing dir keeps its owner's mode
    try:
        probe = State / ".wtest"
        probe.write_text("x"); probe.unlink()
    except PermissionError:
        print(f"STATE dir {State} is not writable. If this is the bastion-data "
              "volume from a v0.1 image, one-time fix:\n"
              "  docker run --rm -v bastion-open-data:/data busybox chmod 1777 /data",
              file=sys.stderr)
        return 20
    new_keys, resolved_keys = diff_baseline(uniq, State)
    for f in uniq:
        f["first_seen_new"] = watch_key(f) in new_keys
    cache_put(State / "last-scan.json", {"version": 1, "meta": meta, "findings": uniq})
    write_report(State / "report.md", uniq, meta, new_keys)
    digest = stable_digest(uniq)
    tmp = State / f"digest.tmp.{os.getpid()}"
    tmp.write_text(digest)
    os.replace(tmp, State / "digest")
    # alert = NEW crit/high/KEV only; 'new' comes from the ever-baseline, so a
    # given finding pings at most once in the tool's lifetime. No re-ping spam.
    if cfg.get("alert"):
        send_alerts(cfg, [f for f in uniq if f["first_seen_new"]
                          and (f["severity"] in ("critical", "high") or f.get("kev"))], [])
    c = collections.Counter(f["severity"] for f in uniq)
    kevh = sum(1 for f in uniq if f.get("kev"))
    hot = sum(1 for f in uniq if f["first_seen_new"] and (f["severity"] in ("critical", "high") or f.get("kev")))
    print(f"BASTION-OPEN {VERSION} {len(uniq)} findings crit={c['critical']} high={c['high']} "
          f"med={c['medium']} kev={kevh} new_hot={hot} resolved_since_last={len(resolved_keys)}")
    print(f"digest={digest}")
    trig = {x.strip() for x in os.environ.get("BASTION_EXIT_ON", "kev,critical").split(",")}
    if trig == {"none"}:
        return 0
    if "any" in trig:
        return 10 if uniq else 0
    if "kev" in trig and kevh:
        return 10
    if "critical" in trig and c["critical"]:
        return 10
    if "high" in trig and c["high"]:
        return 10
    return 0


def stable_digest(findings):
    # KEV membership MUST rotate the digest: a CVE flipping to known-exploited
    # without any other change is the loudest possible news (F17).
    s = hashlib.sha256("|".join(sorted(
        f"{f['target']}:{f.get('package')}:{f.get('cve') or f.get('check_id') or f.get('description','')}:"
        f"{f['severity']}:{'K' if f.get('kev') else '-'}"
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
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text("\n".join(lines))
    os.replace(tmp, path)


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
