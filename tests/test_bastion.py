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
