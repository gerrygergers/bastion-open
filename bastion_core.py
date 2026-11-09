#!/usr/bin/env python3
"""bastion-open core library: distro inventory, OSV + KEV enrichment, report.
Detect-and-report by design; the optional fixer lives in fix.py behind env gates."""
import json, os, re, shutil, subprocess, sys, time, urllib.request
from pathlib import Path

STATE = Path(os.environ.get("BASTION_STATE", "/data"))
STATE.mkdir(parents=True, exist_ok=True)
CACHE_TTL = int(os.environ.get("BASTION_CACHE_DAYS", "7")) * 86400


def http_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "bastion-open/0.1"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def cache_get(path, ttl):
    p = Path(path)
    if p.exists() and time.time() - p.stat().st_mtime < ttl:
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def dpkg_cmp(a, b):
    def key(v):
        v = re.sub(r"^[0-9]+:", "", str(v))
        m = re.match(r"^([\d.]+[~\d.]*)[-+](.*)$", v)
        if not m:
            return ([int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", v) if x], "")
        epoch_rev = m.group(1)
        return ([int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", epoch_rev) if x], m.group(2))
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


def read_dpkg_status(host="/host"):
    """Parse dpkg status files directly - no shell, no arch problems."""
    pkgs = {}
    for f in [Path(host) / "var/lib/dpkg/status"] + sorted((Path(host) / "var/lib/dpkg/status.d").glob("*")) if (Path(host) / "var/lib/dpkg").exists() else []:
        if not f.exists():
            continue
        text = f.read_text(errors="replace")
        for para in text.split("\n\n"):
            if "\nStatus:" not in "\n" + para:
                continue
            fields = dict(
                (m.group(1), m.group(2))
                for m in re.finditer(r"^(Package|Status|Version):\s*(.+)$", para, re.M)
            )
            if not fields.get("Package"):
                continue
            st = fields.get("Status", "")
            if "install ok installed" not in st:
                continue
            pkgs[fields["Package"]] = fields.get("Version", "")
    return pkgs


def host_os(host="/host"):
    try:
        txt = (Path(host) / "etc/os-release").read_text(errors="replace")
    except Exception:
        return None, None, "unknown"
    kv = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', txt, re.M))
    iid, ver = kv.get("ID", "").lower(), kv.get("VERSION_ID", "")
    like = kv.get("ID_LIKE", "")
    if iid == "ubuntu" or (iid == "" and "ubuntu" in like):
        return "Ubuntu", ver, f"ubuntu-{ver}"
    if iid in ("debian", "proxmox") or "debian" in (iid + " " + like):
        return "Debian", ver, f"debian-{ver}"
    return iid or "unknown", ver, f"{iid}-{ver}"


def rpm_inventory(host="/host"):
    """Best-effort rpm listing without executing host binaries."""
    pkgs = {}
    import sqlite3
    db = Path(host) / "var/lib/rpm/rpmdb.sqlite"
    if db.exists():
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
            for n, v, r in con.execute(
                "select name,version,release from (select * from packages order by dbid)"
            ):
                pkgs[n] = f"{v}-{r}"
            con.close()
        except Exception:
            pass
    return pkgs


def kev_set():
    f = STATE / "kev.json"
    c = cache_get(f, 86400)
    if c is None:
        try:
            j = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 60)
            c = sorted(v["cveID"] for v in j.get("vulnerabilities", []))
            f.write_text(json.dumps(c))
        except Exception:
            return set()
    return set(c)


def osv_batch(pairs, eco, rel):
    """[(pkg,ver)] -> {pkg: [(cve, fixed, sev, score)]}.
    Semantics (do not 'simplify'):
    - querybatch does NOT fully version-filter; post-filter ECOSYSTEM fixed events.
    - Ubuntu records: no fixed events; a hit = genuinely affected. versions lists are
      every version ever shipped, so membership tests there are meaningless.
    - Match affected entries by ECOSYSTEM ONLY (Ubuntu vulns span sibling packages).
    - Severity: Ubuntu/Debian bucket field first, then ecosystem urgency, then CVSS."""
    out = {}
    pairs = [(p, v) for p, v in pairs
             if p == "linux-libc-dev" or not (p.startswith("linux-") or p.endswith("-source"))]
    VCACHE = STATE / "vulncache.json"
    cache = cache_get(VCACHE, CACHE_TTL) or {}
    if cache and not any("urg" in v for v in cache.values()):
        cache = {}
    want = f"{eco}:{rel}"
    queries = [{"package": {"name": p, "ecosystem": want}, "version": v} for p, v in pairs]
    hits = {}
    for i in range(0, len(queries), 100):
        body = json.dumps({"queries": queries[i:i + 100]}).encode()
        try:
            req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                         headers={"Content-Type": "application/json"})
            r = json.loads(urllib.request.urlopen(req, timeout=90).read())
            for q, res in zip(queries[i:i + 100], r.get("results", [])):
                ids = [v["id"] for v in res.get("vulns", [])]
                if ids:
                    hits[q["package"]["name"]] = (q["version"], ids)
        except Exception as e:
            print(f"OSV batch fail: {str(e)[:80]}", file=sys.stderr)
    todo = sorted({vid for _, ids in hits.values() for vid in ids if vid not in cache})
    cap = int(os.environ.get("BASTION_OSV_DETAIL_MAX", "400"))
    for n, vid in enumerate(todo[:cap]):
        try:
            full = http_json(f"https://api.osv.dev/v1/vulns/{vid}", 20)
            fixes, urg = [], ""
            for a in full.get("affected", []):
                ecos = a.get("package", {}).get("ecosystem", "")
                if ecos == want or ecos.startswith(want + ":"):
                    for rng in a.get("ranges", []):
                        if rng.get("type") != "ECOSYSTEM":
                            continue
                        fixes += [ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev]
                    urg = urg or str(a.get("ecosystem_specific", {}).get("urgency", ""))
            sev = "unknown"
            for s in full.get("severity", []):
                if s.get("type") in ("Ubuntu", "Debian"):
                    sev = str(s.get("score", "")).lower()
                    break
            if sev == "unknown":
                sev = str(full.get("database_specific", {}).get("severity", "")).lower()
            score = 0.0
            for s in full.get("severity", []):
                if s.get("type", "").startswith("CVSS"):
                    mm = re.search(r"(\d+\.?\d*)\s*$", s.get("score", ""))
                    if mm:
                        score = max(score, float(mm.group(1)))
            sevmap = {"moderate": "medium", "negligible": "low"}
            cache[vid] = {"fixes": fixes, "urg": urg, "sev": sevmap.get(sev, sev if sev in
                        ("critical", "high", "medium", "low") else "unknown"),
                        "score": score, "aliases": full.get("aliases", [])}
        except Exception:
            cache[vid] = {"fixes": [], "urg": "", "sev": "unknown", "score": 0, "aliases": []}
        if n % 60 == 59:
            VCACHE.write_text(json.dumps(cache))
    VCACHE.write_text(json.dumps(cache))
    umap = {"not yet assigned": "medium", "unimportant": "low", "end-of-life": "low",
            "whacked": "low", "highest": "critical", "high": "high", "medium": "medium", "low": "low"}
    for pkg, (ver, ids) in hits.items():
        rows = []
        for vid in ids:
            meta = cache.get(vid, {})
            fixes = meta.get("fixes", [])
            if fixes and all(dpkg_cmp(ver, fx) >= 0 for fx in fixes):
                continue
            sev = meta.get("sev", "unknown")
            if sev == "unknown":
                u = str(meta.get("urg", "")).lower()
                if u in umap:
                    sev = umap[u]
                elif meta.get("score"):
                    s = meta["score"]
                    sev = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
            cve = next((a for a in meta.get("aliases", []) if a.startswith("CVE-")), vid)
            rows.append((cve, ",".join(fixes)[:60] or "no fix released", sev, meta.get("score", 0)))
        if rows:
            out[pkg] = rows
    return out


def probe_urls(urls):
    out = {}
    for u in urls:
        try:
            code = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-m", "12", u],
                                  capture_output=True, text=True).stdout.strip() or "000"
        except Exception:
            code = "000"
        out[u] = code
    return out


def listeners(host="/host"):
    """Ports bound to wildcard addresses, read from /proc/net (state 0A = LISTEN)."""
    out = set()
    for f, wcard in (("tcp", {"00000000"}), ("tcp6", {"00000000000000000000000000000000",
                                                     "00000000000000000000FFFF00000000"})):
        p = Path(host) / f"proc/net/{f}"
        try:
            for line in p.read_text().splitlines()[1:]:
                parts = line.split()
                if parts[3] != "0A":
                    continue
                addr, port = parts[1].rsplit(":", 1)
                if addr in wcard:
                    out.add(int(port, 16))
        except Exception:
            continue
    return sorted(out)


def scan_host(host="/host"):
    eco, rel, oskey = host_os(host)
    res = {"os": oskey, "packages": 0, "findings": [], "error": None}
    if (Path(host) / "var/run/reboot-required").exists():
        res["findings"].append({"target": Path(host).name, "kind": "reboot", "severity": "medium",
                                "package": "kernel", "cve": "", "fix": "reboot",
                                "description": "kernel updated, reboot pending", "kev": False})
    for port in listeners(host):
        if port in (22,):
            continue
        res["findings"].append({"target": Path(host).name, "kind": "exposure", "severity": "info",
                                "package": f"tcp/{port}", "cve": "", "fix": "",
                                "description": f"listening on 0.0.0.0:{port}", "kev": False})
    if eco in ("Ubuntu", "Debian") and rel:
        pkgs = read_dpkg_status(host)
        res["packages"] = len(pkgs)
        if pkgs:
            kev = kev_set()
            vulns = osv_batch(sorted(pkgs.items()), eco, rel)
            for pkg, lst in vulns.items():
                for cve, fixed, sev, score in lst:
                    res["findings"].append({"target": Path(host).name, "kind": "cve-os", "package": pkg,
                                            "installed": pkgs.get(pkg, ""), "cve": cve, "fix": fixed,
                                            "severity": sev, "cvss": score, "kev": cve in kev})
        else:
            res["error"] = "dpkg status unreadable (mount missing or not a Debian/Ubuntu host)"
    elif eco and eco not in ("unknown",):
        res["error"] = f"distro '{eco}' not covered by OSV path yet (use trivy targets for it)"
    else:
        res["error"] = "no /host mount"
    return res


def mark_fixable(res, host="/host"):
    """Chroot apt dry-run, best effort. Absence of data is never treated as fixable."""
    fixable = set()
    pkgs = sorted({f["package"] for f in res["findings"]})
    if not pkgs or not shutil.which("chroot") or os.geteuid() != 0:
        return res
    for i in range(0, len(pkgs), 80):
        try:
            p = subprocess.run(["chroot", host, "apt-get", "-s", "--only-upgrade", "-y"] + pkgs[i:i + 80],
                               capture_output=True, text=True, timeout=120)
            fixable |= {m.group(1).rstrip(":anyarch") for m in
                        re.finditer(r"^Inst (\S+) \[[^\]]*\] \((\S+)", p.stdout, re.M)}
        except Exception:
            pass
    for f in res["findings"]:
        f["fixable"] = f["package"] in fixable
    return res
