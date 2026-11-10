#!/usr/bin/env python3
"""bastion-open core library: distro inventory, OSV + KEV enrichment, listeners,
URL/TLS probing, and a high-precision config benchmark.

Detect-and-report by design: nothing in this file mutates the target system.
The optional fixer lives in fix.py behind env gates. stdlib-only, so it also
runs directly on a host (no pip install) if you prefer that to the container.
"""
import json, os, re, shutil, subprocess, sys, tarfile, time, urllib.parse, urllib.request
from io import BytesIO
from pathlib import Path

VERSION = "0.2.0"
STATE = Path(os.environ.get("BASTION_STATE", "/data"))
STATE.mkdir(parents=True, exist_ok=True)
CACHE_TTL = int(os.environ.get("BASTION_CACHE_DAYS", "7")) * 86400
UA = f"bastion-open/{VERSION}"


# ---------------------------------------------------------------- http + cache

def http_json(url, timeout=30, retries=2):
    """GET a URL as JSON with basic backoff. https-only unless BASTION_ALLOW_HTTP=1."""
    u = urllib.parse.urlparse(url)
    if u.scheme == "http" and os.environ.get("BASTION_ALLOW_HTTP") != "1":
        raise ValueError(f"refusing plain http: {url}")
    if u.scheme not in ("https", "http"):
        raise ValueError(f"refusing non-http scheme: {url}")
    last = None
    for n in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            return json.loads(urllib.request.urlopen(req, timeout=timeout).read())
        except Exception as e:
            last = e
            if n < retries:
                time.sleep(2 * (n + 1))
    raise last


def cache_get(path, ttl):
    p = Path(path)
    if p.exists() and time.time() - p.stat().st_mtime < ttl:
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def cache_put(path, obj):
    """Atomic write so a crash mid-write can't corrupt a cache the next run trusts."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj))
    os.replace(tmp, p)


# ------------------------------------------------------------ version compare

def dpkg_cmp(a, b):
    """Debian version ordering: epoch, then upstream, then revision; '~' sorts
    before everything (including nothing). Returns -1/0/1. Adequate for
    fixed-event filtering; not a full policy implementation."""
    def split(v):
        v = str(v)
        m = re.match(r"^(\d+):(.*)$", v)
        ep, rest = (m.group(1), m.group(2)) if m else ("0", v)
        m2 = re.match(r"^([^-]*)[-](.*)$", rest)
        up, rev = (m2.group(1), m2.group(2)) if m2 else (rest, "")
        return ep, up, rev
    def tokens(s):
        # classes: '~' (own token, every one), digit runs, other-char runs
        return re.findall(r"~|\d+|[^~\d]+", s)
    def key(t):
        # Debian policy order: '~' < end-of-run < letters < other non-alnum <
        # digits (numeric). Tuple classes encode that; end-of-list wins by prefix.
        if t == "~":
            return (0, 0, "")
        if t.isdigit():
            return (3, int(t), "")     # digits sort AFTER any non-digit
        if t[:1].isalpha():
            return (1, 0, t)           # letters before other non-alnum
        return (2, 0, t)
    def cmp_part(x, y):
        # '~' < end-of-run < letters < other non-alnum < digits. Python says a
        # shorter list is smaller, so an exhausted run needs an explicit
        # between-~-and-letters sentinel or '1.0~rc' > '1.0' comes out wrong.
        END = (0.5, 0, "")
        tx = [key(t) for t in tokens(x)] + [END]
        ty = [key(t) for t in tokens(y)] + [END]
        return (tx > ty) - (tx < ty)
    ea, ua, ra = split(a); eb, ub, rb = split(b)
    for x, y in ((int(ea), int(eb)), (ua, ub), (ra, rb)):
        c = (x > y) - (x < y) if isinstance(x, int) else cmp_part(x, y)
        if c:
            return c
    return 0


# --------------------------------------------------------------- distro + inventory

def host_os(host="/host"):
    """-> (name, version, eco_key). eco_key feeds OSV ecosystem queries."""
    try:
        txt = (Path(host) / "etc/os-release").read_text(errors="replace")
    except Exception:
        return None, None, "unknown"
    kv = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', txt, re.M))
    iid, ver = kv.get("ID", "").lower(), kv.get("VERSION_ID", "")
    like = kv.get("ID_LIKE", "")
    allids = iid + " " + like
    if "ubuntu" in allids:
        return "Ubuntu", ver, f"ubuntu-{ver}"
    if "debian" in allids or iid in ("proxmox",):
        return "Debian", ver, f"debian-{ver}"
    if iid in ("fedora",) or "fedora" in like:
        return "Fedora", ver, f"fedora-{ver}"
    if any(x in allids for x in ("rhel", "centos", "rocky", "alma", "amzn")):
        return kv.get("NAME", iid), ver, f"rhat-{iid}-{ver}"
    return iid or "unknown", ver, f"{iid}-{ver}"


def read_dpkg_status(host="/host"):
    """Parse dpkg status files directly - no shell, no executing host binaries."""
    pkgs = {}
    base = Path(host) / "var/lib/dpkg"
    if not base.exists():
        return pkgs
    files = [base / "status"] + sorted((base / "status.d").glob("*")) if (base / "status.d").exists() else [base / "status"]
    for f in files:
        if not f.exists():
            continue
        text = f.read_text(errors="replace")
        for para in text.split("\n\n"):
            fields = dict(
                (m.group(1), m.group(2))
                for m in re.finditer(r"^(Package|Status|Version):\s*(.+)$", para, re.M)
            )
            if not fields.get("Package"):
                continue
            if "install ok installed" not in fields.get("Status", ""):
                continue
            pkgs[fields["Package"]] = fields.get("Version", "")
    return pkgs


def rpm_inventory(host="/host"):
    """RPM packages without executing host binaries. Two layouts: legacy BDB
    exposed as rpmdb.sqlite (SELECT works) and the newer ndbxdbc file whose
    name lies (it is NOT sqlite; the fixed-offset header parse below is)."""
    pkgs = {}
    root = Path(host) / "var/lib/rpm"
    if not root.exists():
        return pkgs
    import sqlite3
    for db in sorted(root.iterdir()):
        head = db.open("rb").read(16)
        if head.startswith(b"SQLite format 3"):
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
                for n, v, r in con.execute(
                    "select name,version,release from (select * from packages order by dbid)"):
                    pkgs[n] = f"{v}-{r}"
                con.close()
            except Exception:
                pass
        elif head.startswith(b"\xda\xbe\xad\xb2") or head.startswith(b"\xb2\xad\xbe\xda"):
            pkgs.update(_parse_ndbxdbc(db))
    return pkgs


def _parse_ndbxdbc(path):
    """Minimal RPM ndbxdbc reader. Layout: 24-byte file header, then 20-byte
    index entries {tag:u32, type:u32, dest:u64, count:u32}; 'dest' is an offset
    into the data section that follows the index. Values are NUL-terminated
    strings. Best effort — caller falls back to the offline trivy hint if this
    yields nothing plausible."""
    import struct
    out = {}
    NAME, VER, REL = 1000, 1046, 1099
    try:
        raw = Path(path).read_bytes()
        endian = ">" if raw[:4] == b"\xda\xbe\xad\xb2" else "<"
        hdr = struct.unpack(endian + "IIII", raw[:16])
        entries_len, data_off = hdr[2], hdr[3]
        base = 24 + entries_len            # data section starts after the 24B header + index
        want = {}
        for off in range(24, 24 + entries_len - 19, 20):
            tag, dtype, dest, count = struct.unpack(endian + "IIQI", raw[off:off + 20])
            if tag in (NAME, VER, REL):
                want.setdefault(tag, []).append(base + dest)
        def rd(pos):
            end = raw.find(b"\x00", pos)
            return raw[pos:end].decode("utf-8", "replace")
        names = sorted((p, rd(p)) for p in want.get(NAME, []))
        vers = sorted(want.get(VER, []))
        rels = sorted(want.get(REL, []))
        for i, (_, n) in enumerate(names):
            v = rd(vers[i]) if i < len(vers) else ""
            r = rd(rels[i]) if i < len(rels) else ""
            out[n] = f"{v}-{r}"
    except Exception:
        return {}
    return out if len(out) > 50 else {}      # sanity: a real db has thousands


def inventory_distro_pkgs(host="/host"):
    """-> (pkgs dict, format 'dpkg'|'rpm'|None)."""
    pkgs = read_dpkg_status(host)
    if pkgs:
        return pkgs, "dpkg"
    pkgs = rpm_inventory(host)
    if pkgs:
        return pkgs, "rpm"
    return {}, None


# ---------------------------------------------------------------------- KEV

def kev_set():
    f = STATE / "kev.json"
    c = cache_get(f, 86400)
    if c is None:
        try:
            j = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 60)
            c = sorted(v["cveID"] for v in j.get("vulnerabilities", []))
            cache_put(f, c)
        except Exception:
            return set()
    return set(c)


# ---------------------------------------------------------------------- OSV

def osv_batch(pairs, eco, rel):
    """[(pkg,ver)] -> {pkg: [(cve, fixed, sev, score, published)]}.
    Semantics (do not 'simplify' — each line was learned expensively):
    - querybatch does NOT fully version-filter; post-filter ECOSYSTEM fixed events.
    - Ubuntu records: no fixed events; a hit = genuinely affected. versions lists are
      every version ever shipped, so membership tests there are meaningless.
    - Match affected entries by ECOSYSTEM ONLY (Ubuntu vulns span sibling packages).
    - Severity: Ubuntu/Debian bucket field first, then ecosystem urgency, then CVSS.
    - Skip linux-* meta packages (flood ~1000 hits); keep linux-libc-dev."""
    out = {}
    pairs = [(p, v) for p, v in pairs
             if p == "linux-libc-dev" or not (p.startswith("linux-") or p.endswith("-source"))]
    VCACHE = STATE / "vulncache.json"
    cache = cache_get(VCACHE, CACHE_TTL) or {}
    if cache and not any("pub" in v for v in cache.values()):
        cache = {}                              # pre-0.2 shape: rebuild, don't trust
    want = f"{eco}:{rel}"
    queries = [{"package": {"name": p, "ecosystem": want}, "version": v} for p, v in pairs]
    hits = {}
    for i in range(0, len(queries), 100):
        body = json.dumps({"queries": queries[i:i + 100]}).encode()
        try:
            req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                         headers={"Content-Type": "application/json", "User-Agent": UA})
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
                    # score may be a float OR a "CVSS:3.1/AV:N/..." vector string —
                    # only the leading-float shape carries a number
                    mm = re.search(r"(\d+\.?\d*)\s*$", str(s.get("score", "")))
                    if mm:
                        score = max(score, float(mm.group(1)))
            sevmap = {"moderate": "medium", "negligible": "low"}
            cache[vid] = {"fixes": fixes, "urg": urg, "sev": sevmap.get(sev, sev if sev in
                        ("critical", "high", "medium", "low") else "unknown"),
                        "score": score, "aliases": full.get("aliases", []),
                        "pub": full.get("published", "")}
        except Exception:
            cache[vid] = {"fixes": [], "urg": "", "sev": "unknown", "score": 0, "aliases": [], "pub": ""}
        if n % 60 == 59:
            cache_put(VCACHE, cache)
    cache_put(VCACHE, cache)
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
            rows.append((cve, ",".join(fixes)[:60] or "no fix released", sev,
                         meta.get("score", 0), meta.get("pub", "")))
        if rows:
            out[pkg] = rows
    return out


# ------------------------------------------------------------- network probing

SAFE_NAME = re.compile(r"^[A-Za-z0-9._+:@/~-]{1,255}$")

def probe_urls(urls):
    """-> {url: {"code", "tls_expiry_days"}}. TLS cert expiry is checked via
    openssl s_client (present in the container image)."""
    out = {}
    for u in urls:
        rec = {"code": "000", "tls_expiry_days": None}
        try:
            if not SAFE_NAME.match(u):
                rec["code"] = "bad-url"
                out[u] = rec
                continue
            code = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                   "-m", "12", "-L", "--", u],
                                  capture_output=True, text=True).stdout.strip() or "000"
            rec["code"] = code
        except Exception:
            pass
        if u.startswith("https://"):
            try:
                host_ = urllib.parse.urlsplit(u).hostname
                port = urllib.parse.urlsplit(u).port or 443
                p = subprocess.run(
                    ["openssl", "s_client", "-servername", host_, "-connect", f"{host_}:{port}"],
                    input=b"", capture_output=True, timeout=12)
                m = re.search(rb"notAfter=(.*\n)", p.stderr)
                if m:
                    from email.utils import parsedate_to_datetime
                    import datetime as dt
                    exp = parsedate_to_datetime(m.group(1).decode(errors="replace").strip())
                    rec["tls_expiry_days"] = (exp - dt.datetime.now(dt.timezone.utc)).days
            except Exception:
                pass
        out[u] = rec
    return out


def listeners(host="/host"):
    """Ports bound to wildcard addresses, from /proc/net (state 0A = LISTEN).
    Docker's bind of /:/host is recursive, so /host/proc is the host's procfs
    and this shows the HOST's sockets even though the container has its own
    netns. If /proc is absent (partial mount) you get [] — a scan-gap, not clean."""
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


# ---------------------------------------------------------- config benchmark
# High-precision static checks only: each one can be verified by opening the
# cited file. No check here tries to judge "good practice" beyond defaults.

def _read(host, *parts):
    try:
        return (Path(host).joinpath(*parts)).read_text(errors="replace")
    except Exception:
        return ""


def _ssh_config_value(host, key):
    """Effective sshd value: ssh_config.d-style drops + sshd_config, first match wins
    (sshd semantics: first obtained value wins). Returns None if not set (=distro default)."""
    texts = [_read(host, "etc", "ssh", "sshd_config")]
    d = Path(host) / "etc/ssh/sshd_config.d"
    if d.is_dir():
        texts += [f.read_text(errors="replace") for f in sorted(d.glob("*.conf"))]
    for t in texts:
        m = re.search(rf"^\s*{key}\s+(\S+)", t, re.M | re.I)
        if m:
            return m.group(1).lower()
    return None


def configbench(host="/host"):
    """-> list of finding dicts (kind=config-check)."""
    out = []
    hname = Path(host).name or "host"
    def add(cid, sev, desc, fix, evidence):
        out.append({"target": hname, "kind": "config-check", "check_id": cid,
                    "severity": sev, "description": desc, "fix": fix, "evidence": evidence})

    # sshd
    if _ssh_config_value(host, "PermitRootLogin") == "yes":
        add("SSH-01", "high", "sshd PermitRootLogin yes", "set PermitRootLogin prohibit-password (or no)",
            "/etc/ssh/sshd_config(.d)")
    if _ssh_config_value(host, "X11Forwarding") == "yes":
        add("SSH-02", "medium", "sshd X11Forwarding yes", "X11Forwarding no unless you need X11", "/etc/ssh/sshd_config(.d)")
    if _ssh_config_value(host, "PermitEmptyPasswords") == "yes":
        add("SSH-03", "critical", "sshd PermitEmptyPasswords yes", "PermitEmptyPasswords no", "/etc/ssh/sshd_config(.d)")

    # world-writable + permissions on sensitive paths
    for p in ("/etc/ssh", "/etc/cron.d", "/etc", "/usr/local/bin", "/etc/sudoers.d"):
        fp = Path(host) / p.lstrip("/")
        try:
            if fp.is_dir() and (fp.stat().st_mode & 0o022):
                add("PERM-01", "high", f"{p} is world-writable", "chmod o-w", str(fp.stat().st_mode & 0o777))
        except Exception:
            pass
    try:
        st = (Path(host) / "etc/shadow").stat()
        if st.st_mode & 0o037:
            add("PERM-02", "high", "/etc/shadow readable by group/other", "chmod 640 root/shadow or 000", str(st.st_mode & 0o777))
    except Exception:
        pass
    t = Path(host) / "tmp"
    try:
        if t.exists() and not (t.stat().st_mode & 0o1000):
            add("PERM-03", "medium", "/tmp lacks the sticky bit", "chmod 1777 /tmp", str(t.stat().st_mode & 0o777))
    except Exception:
        pass
    if (Path(host) / "etc/sudoers").exists():
        try:
            s = (Path(host) / "etc/sudoers").stat()
            if s.st_mode & 0o777 not in (0o440, 0o400):
                add("PERM-04", "high", "/etc/sudoers mode not 0440", "chmod 0440 /etc/sudoers", str(s.st_mode & 0o777))
        except Exception:
            pass

    # crontab hygiene
    for f in sorted((Path(host) / "etc/cron.d").glob("*")) if (Path(host) / "etc/cron.d").is_dir() else []:
        try:
            if f.stat().st_mode & 0o022:
                add("CRON-01", "high", f"{f} world-writable cron file", "chmod go-w", str(f))
        except Exception:
            pass

    # empty root password (needs shadow readable; scanner container runs as root)
    shadow = _read(host, "etc", "shadow")
    if re.search(r"^root:[^:!]*::", shadow, re.M):
        add("AUTH-01", "critical", "root password hash is empty", "passwd root", "/etc/shadow")
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) > 6 and parts[2] == "0" and parts[0] != "root":
            add("AUTH-02", "high", f"non-root UID 0 account: {parts[0]}", "userdel or give it a unique uid", "/etc/passwd")
    # accounts that can log in with NO password: authoritative check is
    # shadow's empty hash field (passwd's x just means "see shadow").
    try:
        for line in (Path(host) / "etc/shadow").read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) > 1 and parts[1] == "" and parts[0] not in ("sync", "halt", "shutdown"):
                add("AUTH-03", "medium", f"account {parts[0]} has no password (logs in without one)",
                    "lock it: passwd -l " + parts[0], "/etc/shadow")
    except Exception:
        pass

    # core dumps setuid
    try:
        if _read(host, "proc", "sys", "fs", "suid_dumpable").strip() == "2":
            add("KER-01", "medium", "fs.suid_dumpable=2 (setuid binaries may dump core)", "sysctl fs.suid_dumpable=0", "/proc/sys/fs/suid_dumpable")
    except Exception:
        pass

    # forward-only inventory gap: distro family with no package db found
    name, ver, _ = host_os(host)
    pkgs, fmt = inventory_distro_pkgs(host)
    if name in ("Ubuntu", "Debian", "Fedora") and not pkgs:
        add("INV-01", "medium", f"{name} host with no readable package database",
            "mount / fully (or check your transport): package CVEs cannot be assessed", "/var/lib/dpkg or /var/lib/rpm")
    return out


# ----------------------------------------------------------------- host scan

def scan_host(host="/host", do_configbench=True):
    eco, rel, oskey = host_os(host)
    res = {"os": oskey, "packages": 0, "pkg_format": None, "findings": [], "error": None}
    if (Path(host) / "var/run/reboot-required").exists():
        res["findings"].append({"target": Path(host).name, "kind": "reboot", "severity": "medium",
                                "package": "kernel", "cve": "", "fix": "reboot at next window",
                                "description": "kernel updated, reboot pending", "kev": False})
    for port in listeners(host):
        if port in (22,):
            continue
        res["findings"].append({"target": Path(host).name, "kind": "exposure", "severity": "info",
                                "package": f"tcp/{port}", "cve": "", "fix": "",
                                "description": f"listening on 0.0.0.0:{port}", "kev": False})
    pkgs, fmt = inventory_distro_pkgs(host)
    res["pkg_format"] = fmt
    if fmt:
        res["packages"] = len(pkgs)
        kev = kev_set()
        vulns = {}
        if eco in ("Ubuntu", "Debian") and rel:
            vulns = osv_batch(sorted(pkgs.items()), eco, rel)
        elif eco.startswith("fedora-") or eco.startswith("rhat-"):
            # OSV has Fedora/Rocky/Alma data under distinct ecosystems; try the
            # closest one — zero hits is handled as a scan-gap below.
            fam, _, ver_ = eco.split("-", 2)
            eco_name = {"fedora": "Fedora", "rocky": "Rocky Linux", "almalinux": "AlmaLinux"}.get(fam)
            if eco_name and ver_:
                vulns = osv_batch(sorted(pkgs.items()), eco_name, ver_)
        for pkg, lst in vulns.items():
            for cve, fixed, sev, score, pub in lst:
                res["findings"].append({"target": Path(host).name, "kind": "cve-os", "package": pkg,
                                        "installed": pkgs.get(pkg, ""), "cve": cve, "fix": fixed,
                                        "severity": sev, "cvss": score, "kev": cve in kev, "pub": pub})
        if fmt == "rpm" and eco not in ("Ubuntu", "Debian") and not vulns and pkgs:
            res["error"] = f"distro '{eco}' has {len(pkgs)} rpm packages but no OSV coverage here; use trivy targets for it"
    elif eco in ("Ubuntu", "Debian") or eco.startswith(("fedora", "rhat")):
        res["error"] = "package database unreadable (mount missing or partial)"
    elif eco and eco != "unknown":
        res["error"] = f"distro '{eco}' not covered by the OSV path (use trivy targets for it)"
    else:
        res["error"] = "no /host mount or /etc/os-release"
    if do_configbench:
        res["findings"].extend(configbench(host))
    return res


def mark_fixable(res, host="/host"):
    """Chroot apt dry-run, best effort (Debian/Ubuntu only). Absence of data is
    never treated as fixable."""
    fixable = set()
    pkgs = sorted({f["package"] for f in res["findings"] if f.get("kind") == "cve-os"})
    if not pkgs or not shutil.which("chroot") or os.geteuid() != 0:
        for f in res["findings"]:
            f.setdefault("fixable", False)
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
        f["fixable"] = f.get("package") in fixable
    return res


# ---------------------------------------------------------- inventory packing
# Used by the ssh fleet mode and by `bastion.py collect` on a remote box.

KEEP = ["etc/os-release", "etc/ssh/sshd_config", "etc/passwd", "etc/group",
        "etc/shadow", "etc/sudoers", "proc/net/tcp", "proc/net/tcp6",
        "proc/sys/fs/suid_dumpable", "var/run/reboot-required", "tmp"]
KEEP_GLOBS = [("etc/ssh/sshd_config.d", "*.conf"), ("etc/cron.d", "*"),
              ("var/lib/dpkg/status.d", "*"), ("var/lib/rpm", "*")]
# never pack these, wherever a glob might catch them (private key material)
EXCLUDE = re.compile(r"(^|/)(.+key.*|.*\.pem|shadow\.old)$")


def _tar_add_file(tf, f, arcname):
    """procfs files stat as size 0 — read the bytes or we'd pack empties."""
    try:
        data = f.read_bytes()
    except Exception:
        return
    ti = tarfile.TarInfo(arcname)
    ti.size = len(data)
    ti.mtime = 0
    ti.mode = f.stat().st_mode & 0o7777
    tf.addfile(ti, BytesIO(data))


def pack_inventory(src_root, out_path):
    """tar.gz of the small, security-relevant paths under src_root. Private key
    material is never included. Best effort: unreadable files are skipped (the
    scanner flags what's missing as a scan-gap rather than scoring it clean)."""
    src = Path(src_root)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as tf:
        for rel in KEEP:
            p = src / rel
            if p.is_file() and not EXCLUDE.search(rel):
                _tar_add_file(tf, p, "host/" + rel)
        for d, g in KEEP_GLOBS:
            dp = src / d
            if dp.is_dir():
                for f in sorted(dp.glob(g))[:500]:
                    if f.is_file() and not EXCLUDE.search(str(f.relative_to(src))):
                        _tar_add_file(tf, f, "host/" + str(f.relative_to(src)))
        st = src / "var/lib/dpkg/status"
        if st.is_file():
            _tar_add_file(tf, st, "host/var/lib/dpkg/status")
    return out


def unpack_inventory(tgz_path, dest):
    """Safe extract: reject path traversal, absolute paths, links/devices.
    This tar is OURS (made by pack_inventory) but the scan container should
    still never be a soft-touch on arbitrary bytes."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz_path, "r:gz") as tf:
        for m in tf.getmembers():
            name = m.name
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError(f"unsafe path in inventory tar: {name}")
            if not (m.isfile() or m.isdir()):
                continue
            tf.extract(m, dest, filter="data")
    return dest / "host"
