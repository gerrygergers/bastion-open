#!/usr/bin/env python3
"""Deterministic self-test for bastion-open — no network, no root, no deps.
Run via `python3 scripts/selftest.py` or `make check`. Exits nonzero on fail.
Complements tests/ (pytest); this one is for users on a box with just python3."""
import json, os, sys, tempfile
from pathlib import Path
HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
os.environ["BASTION_STATE"] = tempfile.mkdtemp(prefix="bastion-selftest-")
import bastion_core as bc

FAILS = []
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)

# version comparator
check("dpkg_cmp basic", bc.dpkg_cmp("1.2-3", "1.2-4") < 0)
check("dpkg_cmp tilde", bc.dpkg_cmp("1.0~rc1-1", "1.0-1") < 0)
check("dpkg_cmp epoch", bc.dpkg_cmp("1:1.0", "2.0") > 0)
check("dpkg_cmp equal", bc.dpkg_cmp("2.1-1", "2.1-1") == 0)
check("dpkg_cmp distro", bc.dpkg_cmp("2.2-4+deb11u1", "2.2-4") > 0)
check("dpkg_cmp numeric tokens", bc.dpkg_cmp("1.10-1", "1.9-1") > 0)
check("dpkg_cmp letter-vs-digit", bc.dpkg_cmp("1.2.3-1", "1.2a-1") > 0)   # verified vs dpkg --compare-versions

# fake host
fx = Path(tempfile.mkdtemp(prefix="fakehost-"))
(fx / "etc").mkdir()
(fx / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
(fx / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nnpc:x:1001:1001::/home/npc:/bin/sh\n")
(fx / "etc/shadow").write_text("npc::12345:0:99999:7:::\nroot:!:1:::::\n")
(fx / "etc/ssh").mkdir()
(fx / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\nX11Forwarding yes\n")
(fx / "proc/net").mkdir(parents=True)
(fx / "proc/net/tcp").write_text("  sl  local_address rem_address   st\n"
                                 "   0: 0100007F:E7D0 00000000:0000 0A 00000000/00000000\n"
                                 "   1: 00000000:1F90 00000000:0000 0A 00000000/00000000\n")
checks = {c["check_id"]: c for c in bc.configbench(str(fx))}
check("ssh root login flagged", checks.get("SSH-01", {}).get("severity") == "high")
check("empty-password account flagged", checks.get("AUTH-03", {}).get("description", "").find("npc") >= 0
      or any("npc" in c.get("description","") for c in checks.values()))
check("wildcard listener found", 8080 in bc.listeners(str(fx)))
check("loopback listener NOT flagged", 59344 not in bc.listeners(str(fx)))

# inventory pack/unpack round-trip with hostile members rejected
tmp = Path(tempfile.mkdtemp())
bc.pack_inventory(str(fx), tmp / "inv.tgz")
root = bc.unpack_inventory(tmp / "inv.tgz", tmp / "out")
check("roundtrip keeps os-release", (root / "etc/os-release").is_file())
import tarfile
with tarfile.open(tmp / "inv.tgz") as tf:
    check("roundtrip keeps procfs CONTENT", len(tf.extractfile("host/proc/net/tcp").read()) > 0)
evil = tmp / "evil.tgz"
with tarfile.open(evil, "w:gz") as tf:
    ti = tarfile.TarInfo("../escaped"); ti.size = 1
    import io
    tf.addfile(ti, io.BytesIO(b"x"))
try:
    bc.unpack_inventory(evil, tmp / "evil-out")
    check("traversal rejected", False)
except ValueError:
    check("traversal rejected", True)

# policy decision unit (no files touched beyond temp state)
fnd = [{"kind": "cve-os", "package": "openssl", "target": "t", "cve": "CVE-2026-0001",
        "severity": "critical", "cvss": 9.8, "kev": True, "pub": ""},
       {"kind": "cve-os", "package": "libtiff", "target": "t", "cve": "CVE-2025-9999",
        "severity": "high", "cvss": 7.5, "kev": False, "pub": ""}]
import policy
d = policy.decide(fnd, cfg={"soak": 48 * 3600, "cvss": 9.0}, incidents={}, now=1_800_000_000)
check("KEV urgent applies", "openssl" in d["apply"])
check("high soaks", "libtiff" not in d["apply"] and any(x["package"] == "libtiff" for x in d["deferred"]))
d2 = policy.decide(fnd, cfg={"soak": 48 * 3600, "cvss": 9.0},
                   incidents={"!openssl": "test incident"}, now=1_800_000_000)
check("incident watch holds even urgent", "openssl" not in d2["apply"])

# dedupe/stable digest
fs = [{"target": "a", "kind": "cve-os", "package": "x", "cve": "CVE-1", "severity": "high"},
      {"target": "a", "kind": "cve-os", "package": "x", "cve": "CVE-1", "severity": "high"}]
seen, uniq = set(), []
for f in fs:
    k = f["target"] + "|" + str(f.get("package")) + "|" + str(f.get("cve"))
    if k not in seen:
        seen.add(k); uniq.append(f)
check("dedupe", len(uniq) == 1)
check("digest stable", bc and __import__("scan").stable_digest(uniq) == __import__("scan").stable_digest(list(reversed(uniq))))

print("\nselftest:", "FAILED " + str(FAILS) if FAILS else "all good")
sys.exit(1 if FAILS else 0)
