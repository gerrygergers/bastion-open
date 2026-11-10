#!/usr/bin/env python3
"""Fix policy — decides WHICH packages the opt-in fixer may apply, not just whether
it runs at all. The same discipline we run internally, published (2026-11-10):

  URGENT  (CISA KEV hit | severity critical | CVSS >= BASTION_URGENT_CVSS [9.0])
          -> apply now, unless the package sits under a supply-chain incident
             watch, in which case even urgent is HELD for a human.
  ALL OTHERS fixable -> soak BASTION_SOAK_HOURS [48] before applying. The clock
          starts at max(first seen here, when the fix advisory was published),
          so a brand-new upstream release always soaks, and a mature fix on a
          box you just discovered waits at most 48h from first sight.
  INCIDENT WATCH: names listed unresolved in config/incidents.yaml (xz-style
          poisoned releases) are never auto-applied. The KEV *catalog product*
          matches are deliberately NOT incident signals — they'd block e.g.
          'kernel' forever.

State: <BASTION_STATE>/fix-policy.json (soak queue + applied log).
fix.py calls decide(); scan.py/report surfaces the queue. Pure stdlib.
"""
import json, os, time
from pathlib import Path

STATE = Path(os.environ.get("BASTION_STATE", "/data"))
NOW = time.time()


def _cfg():
    return {"soak": float(os.environ.get("BASTION_SOAK_HOURS", "48")) * 3600,
            "cvss": float(os.environ.get("BASTION_URGENT_CVSS", "9.0"))}


def _incidents():
    """{pkgname_lower: reason} for unresolved entries in config/incidents.yaml.
    Shape: incidents: [{packages: [..], reason: str, resolved: bool}]"""
    out = {}
    for cand in (Path(os.environ.get("BASTION_CONFIG", "/app/config/config.yaml")).parent / "incidents.yaml",
                 Path(__file__).parent / "config" / "incidents.yaml"):
        try:
            try:
                import yaml
                data = yaml.safe_load(cand.read_text()) or {}
            except ImportError:
                data = json.loads(cand.read_text().strip() or "{}")  # json is valid yaml anyway
            for e in data.get("incidents", []):
                if not e.get("resolved"):
                    for p in e.get("packages", []):
                        out[str(p).lower()] = e.get("reason", "incident")
            break
        except FileNotFoundError:
            continue
        except Exception:
            break
    return out


def load():
    try:
        st = json.loads((STATE / "fix-policy.json").read_text())
        if st.get("version") == 1:
            return st
    except Exception:
        pass
    return {"version": 1, "pending": {}, "applied_log": []}


def save(st):
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = STATE / "fix-policy.json.tmp"
    tmp.write_text(json.dumps(st, indent=1, default=str))
    tmp.replace(STATE / "fix-policy.json")


def _pub_ts(iso):
    if not iso:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def decide(findings):
    """findings = list from last-scan.json. Returns {"apply": set(packages),
    "deferred": [{package, reason, eta_h}]}."""
    cfg = _cfg()
    st = load()
    incidents = _incidents()
    grouped = {}
    for f in findings:
        if f.get("kind") != "cve-os" or not f.get("package"):
            continue
        g = grouped.setdefault(f["package"], {"cves": [], "kev": False, "sev": "unknown",
                                              "score": 0.0, "pub": None})
        g["cves"].append(f.get("cve") or "?")
        g["kev"] = g["kev"] or bool(f.get("kev"))
        if f.get("severity") == "critical":
            g["sev"] = "critical"
        elif f.get("severity") == "high" and g["sev"] != "critical":
            g["sev"] = "high"
        g["score"] = max(g["score"], float(f.get("cvss") or 0))
        p = _pub_ts(f.get("pub"))
        if p and (g["pub"] is None or p > g["pub"]):
            g["pub"] = p

    def urgent(g):
        return bool(g["kev"] or g["sev"] == "critical" or g["score"] >= cfg["cvss"])

    apply_set, deferred, pending = set(), [], {}
    for pkg, g in grouped.items():
        prior = st["pending"].get(pkg)
        first_seen = prior["first_seen"] if prior else NOW
        start = max(first_seen, g["pub"]) if g["pub"] else first_seen
        hit = incidents.get(pkg.lower())
        if hit:
            reason = ("URGENT but under supply-chain incident watch (" + hit + ") - review manually"
                      if urgent(g) else "supply-chain incident watch: " + hit)
            eta = None
        elif urgent(g):
            apply_set.add(pkg)
            # keep the pending entry; note_applied()/pruning clears it once the
            # upgrade actually lands (no apt candidate = retried next run)
            continue
        elif NOW - start >= cfg["soak"]:
            apply_set.add(pkg)  # matured; same bookkeeping as above
            continue
        else:
            reason = "%sh soak (fix published %s, seen %s)" % (
                int(cfg["soak"] / 3600),
                time.strftime("%Y-%m-%d", time.gmtime(g["pub"])) if g["pub"] else "unknown",
                time.strftime("%Y-%m-%d", time.gmtime(first_seen)))
            eta = round((cfg["soak"] - (NOW - start)) / 3600, 1)
        pending[pkg] = {"first_seen": first_seen, "pkg": pkg, "cves": sorted(set(g["cves"]))[:8],
                        "kev": g["kev"], "severity": g["sev"], "cvss": g["score"],
                        "reason": reason, "eta_h": eta}
        deferred.append({"package": pkg, "reason": reason, "eta_h": eta, "severity": g["sev"]})
    for key in list(st["pending"].keys()):
        if key not in grouped and key not in pending:
            st["pending"].pop(key)
    st["pending"].update(pending)
    save(st)
    return {"apply": apply_set, "deferred": deferred}


def note_applied(pkgs):
    st = load()
    for p in pkgs:
        st["pending"].pop(p, None)
    st.setdefault("applied_log", []).append({"ts": NOW, "pkgs": sorted(pkgs)})
    st["applied_log"] = st["applied_log"][-200:]
    save(st)


if __name__ == "__main__":
    scan = json.loads((STATE / "last-scan.json").read_text())
    d = decide(scan.get("findings", []))
    print("policy apply:", sorted(d["apply"]) or "none")
    for x in d["deferred"][:20]:
        print("DEFERRED", x["package"], x["reason"], "eta=", x["eta_h"])
    print("deferred total:", len(d["deferred"]))
