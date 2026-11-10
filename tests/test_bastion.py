"""bastion-open test suite: fake hosts in tmpdirs, no network, no root.
CI runs this on every push (stdlib+pytest only)."""
import json, os, sys, tarfile, tempfile, io
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["BASTION_STATE"] = tempfile.mkdtemp(prefix="bastion-test-")
import bastion_core as bc
import policy


@pytest.fixture
def fake_host(tmp_path):
    h = tmp_path / "host"
    (h / "etc/ssh").mkdir(parents=True)
    (h / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (h / "var/lib/dpkg").mkdir(parents=True)
    (h / "var/lib/dpkg/status").write_text(
        "Package: openssl\nStatus: install ok installed\nVersion: 3.5.0-1\n\n"
        "Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n\n"
        "Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n")
    (h / "etc/ssh/sshd_config").write_text("PermitRootLogin no\nX11Forwarding no\nPasswordAuthentication yes\n")
    (h / "etc/shadow").write_text("root:!:19000:0:99999:7:::\ndebian:!:19000:0:99999:7:::\n")
    (h / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\ndebian:x:1000:1000::/home/debian:/bin/bash\n")
    (h / "proc/net").mkdir(parents=True)
    (h / "proc/net/tcp").write_text("  sl  local_address rem_address   st\n"
        "   0: 00000000:1F90 00000000:0000 0A 00000000/00000000\n")
    return h


def test_host_os(fake_host):
    name, ver, key = bc.host_os(str(fake_host))
    assert (name, key) == ("Debian", "debian-13")


def test_dpkg_status_parsing(fake_host):
    pkgs = bc.read_dpkg_status(str(fake_host))
    assert pkgs == {"openssl": "3.5.0-1", "bash": "5.2-1"}   # removed package excluded


def test_configbench_clean_host(fake_host):
    checks = bc.configbench(str(fake_host))
    ids = {c["check_id"] for c in checks}
    assert "SSH-01" not in ids                      # PermitRootLogin no = quiet
    assert all(c["severity"] != "critical" for c in checks)


def test_configbench_dirty_host(tmp_path):
    h = tmp_path / "h"
    (h / "etc/ssh").mkdir(parents=True)
    (h / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\nPermitEmptyPasswords yes\n")
    (h / "etc/shadow").write_text("npc::19000:0:99999:7:::\n")
    ids = {c["check_id"]: c for c in bc.configbench(str(h))}
    assert ids["SSH-01"]["severity"] == "high"
    assert ids["SSH-03"]["severity"] == "critical"
    assert any("npc" in c["description"] for c in ids.values())


def test_listeners(fake_host):
    assert bc.listeners(str(fake_host)) == [8080]


@pytest.mark.parametrize("a,b,exp", [
    ("1.2-3", "1.2-4", -1), ("1.0~rc1", "1.0", -1), ("1:1.0", "2.0", 1),
    ("2.1-1", "2.1-1", 0), ("1.10", "1.9", 1), ("2.2-4+deb11u1", "2.2-4", 1),
    ("1.0~~", "1.0~", -1),
])
def test_dpkg_cmp(a, b, exp):
    assert bc.dpkg_cmp(a, b) == exp


def test_pack_unpack_roundtrip(fake_host, tmp_path):
    tgz = tmp_path / "i.tgz"
    bc.pack_inventory(str(fake_host), tgz)
    root = bc.unpack_inventory(tgz, tmp_path / "out")
    assert (root / "etc/os-release").is_file()
    assert (root / "var/lib/dpkg/status").read_text().find("openssl") >= 0


def test_unpack_rejects_traversal(tmp_path):
    evil = tmp_path / "e.tgz"
    with tarfile.open(evil, "w:gz") as tf:
        ti = tarfile.TarInfo("host/../../etc/pwn"); ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        bc.unpack_inventory(evil, tmp_path / "out")


def test_pack_excludes_private_keys(tmp_path):
    h = tmp_path / "h"
    (h / "etc/ssh").mkdir(parents=True)
    (h / "etc/ssh/ssh_host_ed25519_key").write_text("PRIVATE")
    (h / "etc/ssh/sshd_config").write_text("x\n")
    tgz = tmp_path / "k.tgz"
    bc.pack_inventory(str(h), tgz)
    with tarfile.open(tgz) as tf:
        names = tf.getnames()
    assert not any("ssh_host" in n and n.endswith("key") for n in names)
    assert "host/etc/ssh/sshd_config" in names


def test_policy_decision():
    fnd = [{"kind": "cve-os", "package": "openssl", "target": "t", "cve": "CVE-2026-1",
            "severity": "critical", "cvss": 9.8, "kev": True, "pub": ""},
           {"kind": "cve-os", "package": "libtiff", "target": "t", "cve": "CVE-2025-1",
            "severity": "high", "cvss": 7.5, "kev": False, "pub": ""},
           {"kind": "cve-os", "package": "weird", "target": "t", "cve": "CVE-2026-2",
            "severity": "critical", "cvss": 0, "kev": False, "pub": ""}]
    d = policy.decide(fnd, cfg={"soak": 48 * 3600, "cvss": 9.0}, incidents={}, now=1_800_000_000)
    assert "openssl" in d["apply"]
    assert "libtiff" not in d["apply"]
    assert "weird" not in d["apply"]          # bare critical w/o score soaks
    d2 = policy.decide(fnd, cfg={"soak": 48 * 3600, "cvss": 9.0},
                       incidents={"!openssl": "malware advisory"}, now=1_800_000_000)
    assert "openssl" not in d2["apply"]
    # plain (curated) names match fuzzily both ways, len>=4; "!" = exact only
    d3 = policy.decide(fnd, cfg={"soak": 48 * 3600, "cvss": 9.0},
                       incidents={"openssl": "xz-style"}, now=1_800_000_000)
    assert "openssl" not in d3["apply"]
    d4 = policy.decide(fnd, cfg={"soak": 48 * 3600, "cvss": 9.0},
                       incidents={"!ssl": "exact-only"}, now=1_800_000_000)
    assert "openssl" in d4["apply"]          # "!" names never substring-match


def test_soak_matures(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_STATE", str(tmp_path))
    import importlib; importlib.reload(policy)
    fnd = [{"kind": "cve-os", "package": "x", "target": "t", "cve": "CVE", "severity": "medium",
            "cvss": 5, "kev": False, "pub": ""}]
    old = 1_000_000_000
    d = policy.decide(fnd, cfg={"soak": 3600, "cvss": 9.0}, incidents={}, now=old)
    assert not d["apply"]
    d2 = policy.decide(fnd, cfg={"soak": 3600, "cvss": 9.0}, incidents={}, now=old + 7200)
    assert "x" in d2["apply"]
    importlib.reload(policy)                  # restore global state for other tests


def test_fedora_not_pretends_clean(tmp_path, monkeypatch):
    h = tmp_path / "rh"
    (h / "etc").mkdir(parents=True)
    (h / "etc/os-release").write_text('ID=fedora\nVERSION_ID="41"\n')
    monkeypatch.setattr(bc, "rpm_inventory", lambda host="": {})   # no readable rpmdb
    monkeypatch.setattr(bc, "configbench", lambda host="": [])
    res = bc.scan_host(str(h))
    assert res["error"] and ("fedora" in res["error"].lower() or "package" in res["error"].lower())


def test_stable_digest_order_independent():
    import scan
    fs = [{"target": "a", "kind": "cve-os", "package": "x", "cve": "C1", "severity": "high"},
          {"target": "b", "kind": "cve-os", "package": "y", "cve": "C2", "severity": "low"}]
    assert scan.stable_digest(fs) == scan.stable_digest(list(reversed(fs)))


# ---- regression coverage for the 2026-11-10 adversarial-review fixes ----

def test_sshd_dropin_precedence(tmp_path):        # F16: drop-in wins over main file
    h = tmp_path / "h"
    (h / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (h / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n")
    (h / "etc/ssh/sshd_config.d/99-hard.conf").write_text("PermitRootLogin yes\n")
    ids = {c["check_id"] for c in bc.configbench(str(h))}
    assert "SSH-01" in ids


def test_auth_root_hashed_not_flagged(tmp_path):   # F8: hashed root w/ empty field 3 = no AUTH-01
    h = tmp_path / "h"
    (h / "etc").mkdir(parents=True)
    (h / "etc/shadow").write_text("root:$6$abc$def:19000:0:99999:7:::\n")
    (h / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    ids = {c["check_id"] for c in bc.configbench(str(h))}
    assert "AUTH-01" not in ids


def test_auth_empty_root_and_uid0(tmp_path):       # F7/F8 true positives
    h = tmp_path / "h"
    (h / "etc").mkdir(parents=True)
    (h / "etc/shadow").write_text("root::19000:0:99999:7:::\n")
    (h / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\nadmin:x:0:0::/home/admin:/bin/bash\n")
    checks = bc.configbench(str(h))
    ids = {c["check_id"] for c in checks}
    assert "AUTH-01" in ids
    assert "AUTH-02" in ids and any("admin" in c["description"] for c in checks)
    # a pwd-change date of 0 must NOT read as UID 0
    (h / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\nsvc:x:1000:1000::/srv:/bin/sh\n")
    (h / "etc/shadow").write_text("root:!:19000:0:99999:7:::\nsvc:!:0:0:99999:7:::\n")
    ids2 = {c["check_id"] for c in bc.configbench(str(h))}
    assert "AUTH-02" not in ids2


def test_config_findings_dedupe_keeps_instances():  # F9: watch_key includes evidence
    import scan
    fs = [{"target": "h", "kind": "config-check", "check_id": "PERM-01", "severity": "high",
           "description": "/etc/ssh is world-writable", "key_suffix": "/etc/ssh"}
          for _ in range(1)] + [
          {"target": "h", "kind": "config-check", "check_id": "PERM-01", "severity": "high",
           "description": "/etc is world-writable", "key_suffix": "/etc"}]
    assert len({scan.watch_key(f) for f in fs}) == 2


def test_digest_rotates_on_kev_flip():             # F17
    import scan
    f1 = {"target": "h", "kind": "cve-os", "package": "x", "cve": "CVE-1", "severity": "high", "kev": False}
    f2 = dict(f1, kev=True)
    assert scan.stable_digest([f1]) != scan.stable_digest([f2])


def test_policy_pending_cleared_on_apply(tmp_path, monkeypatch):  # F19
    monkeypatch.setenv("BASTION_STATE", str(tmp_path))
    import importlib; importlib.reload(policy)
    fnd = [{"kind": "cve-os", "package": "curl", "target": "t", "cve": "C",
            "severity": "critical", "cvss": 9.8, "kev": True, "pub": ""}]
    policy.decide(fnd, cfg={"soak": 3600, "cvss": 9.0}, incidents={}, now=1_000_000_000)
    st = json.loads((tmp_path / "fix-policy.json").read_text())
    assert "curl" not in st["pending"]            # applied path must not linger
    importlib.reload(policy)


def test_ssh_target_option_injection_rejected():   # S3: '-oProxyCommand=...' hosts refused
    import scan
    r = scan.scan_ssh_target("evil", {"host": "-oProxyCommand=touch /tmp/pwn"})
    assert r["meta"]["os"] == "ssh-fail"
    assert any(f["kind"] == "scan-gap" for f in r["findings"])


def test_baseline_no_flap_alerts(tmp_path):        # F18: gone-then-back is not 'new'
    import scan
    st = tmp_path
    f = [{"target": "h", "kind": "cve-os", "package": "x", "cve": "C", "severity": "high",
          "description": ""}]
    new, _ = scan.diff_baseline(f, st)
    assert new == set()                            # cold start census
    new, _ = scan.diff_baseline([], st)            # disappears
    assert new == set()
    new, _ = scan.diff_baseline(f, st)             # comes back
    assert new == set()                            # ever-baseline: never alerts twice


def test_pack_skips_symlink_plants(tmp_path):      # S2: cron.d symlink to key material
    h = tmp_path / "h"
    (h / "etc/cron.d").mkdir(parents=True)
    (h / "secret").write_text("PRIVATE-KEY-BYTES")
    (h / "etc/cron.d/job").symlink_to(h / "secret")
    (h / "etc/cron.d/real").write_text("0 * * * * root true\n")
    tgz = tmp_path / "s.tgz"
    bc.pack_inventory(str(h), tgz)
    with tarfile.open(tgz) as tf:
        names = tf.getnames()
        assert "host/etc/cron.d/real" in names
        assert not any("job" in n for n in names)
        assert b"PRIVATE-KEY-BYTES" not in b"".join(
            tf.extractfile(m).read() for m in tf.getmembers() if m.isfile())


def test_debian_point_release_queries_serie():     # F2: Debian:12.5 must query Debian:12
    # offline: we only assert the ecosystem string built into the query body
    captured = {}
    import urllib.request as ur
    real = ur.urlopen
    class Resp:
        def read(self): return b'{"results": []}'
    def fake(req, timeout=None):
        captured.setdefault("bodies", []).append(req.data)
        return Resp()
    ur.urlopen = fake
    try:
        bc.osv_batch([("bash", "5.0")], "Debian", "12.5")
    finally:
        ur.urlopen = real
    body = json.loads(captured["bodies"][0])
    assert body["queries"][0]["package"]["ecosystem"] == "Debian:12"


def test_host_os_codename_resolution(tmp_path):    # F3: sid / no VERSION_ID still scans
    h = tmp_path / "sid"
    (h / "etc").mkdir(parents=True)
    (h / "etc/os-release").write_text('ID=debian\nVERSION_CODENAME=sid\n')
    name, ver, key = bc.host_os(str(h))
    assert (name, ver) == ("Debian", "unstable")
