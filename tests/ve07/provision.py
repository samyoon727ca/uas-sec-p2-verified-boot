"""Provision the emulated CC's TPM and data disk for the sealing cases (TC-05 onward).

Plays the factory and the MSS (docs/03 sections 3.2 to 3.5), against swtpm
over TCP with tpm2-tools:

  TPM, once per CC (owner authorization):
    - a persistent ECC P-256 storage key at 0x81000001: the parent of the
      sealed objects, and the key the unseal session is salted to;
    - the anti-rollback epoch, a TPM_NT_BITS index at 0x01000001, written once
      (no bits set) so PolicyNV can read it.
  Sealed objects: a WireGuard private key and a MAVLink signing key, generated
    here, sealed under the parent with authPolicy = PolicyAuthorize(K-CC-POL,
    policyRef) and attributes fixedtpm|fixedparent|adminwithpolicy (no
    userwithauth). Only their SHA-256 values are kept.
  MSS, per release: the approved policy for the release's predicted PCRs and
    epoch, signed with K-CC-POL (tools/approve_policy.py).

swtpm is then shut down, so its state directory can be booted under QEMU, and
the CC data (everything p2-unseal reads) is packed as a tar for the data disk.

For the refusal cases it also provisions a second CC's TPM the same way
(TC-07), commits a newer epoch on a copy of the TPM (TC-08), and packs
modified copies of the CC data, as an attacker with storage access or a
later release would leave them.
"""
from __future__ import annotations

import dataclasses
import hashlib
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import approve_policy as ap  # noqa: E402

KEYS = ("wireguard", "mavlink")
SEALED_ATTRIBUTES = "fixedtpm|fixedparent|adminwithpolicy"
EPOCH_NV_ATTRIBUTES = "nt=bits|ownerwrite|authread|no_da"
DATA_DISK_BYTES = 1024 * 1024


def wireguard_key() -> bytes:
    """A Curve25519 private key, clamped as wg genkey does."""
    k = bytearray(os.urandom(32))
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    return bytes(k)


def free_port_pair() -> int:
    """A TCP port P on localhost with P + 1 also free (the swtpm TCTI uses P + 1 for control)."""
    for _ in range(50):
        with socket.socket() as a, socket.socket() as b:
            a.bind(("127.0.0.1", 0))
            port = a.getsockname()[1]
            try:
                b.bind(("127.0.0.1", port + 1))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port pair for swtpm")


class TcpSwtpm:
    """swtpm on localhost TCP for tpm2-tools; stop() shuts it down so the state can be reused."""

    def __init__(self, state: Path) -> None:
        state.mkdir(parents=True, exist_ok=True)
        self.state = state
        self.port = free_port_pair()
        self.proc = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
             "--server", f"type=tcp,port={self.port},bindaddr=127.0.0.1",
             "--ctrl", f"type=tcp,port={self.port + 1},bindaddr=127.0.0.1",
             "--flags", "not-need-init,startup-clear", "--log", f"file={state}/swtpm-provision.log,level=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.env = dict(os.environ, TPM2TOOLS_TCTI=f"swtpm:host=127.0.0.1,port={self.port}")
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.1).close()
                return
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError("swtpm did not start")

    def tpm2(self, *args: str, cwd: Path) -> str:
        """Run tpm2_<args[0]> against this TPM with owner authorization available (empty in P2)."""
        return subprocess.run(["tpm2_" + args[0], *args[1:]], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout

    def stop(self) -> None:
        if self.proc.poll() is None:
            subprocess.run(["swtpm_ioctl", "--tcp", f"127.0.0.1:{self.port + 1}", "-s"], capture_output=True)
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        (self.state / ".lock").unlink(missing_ok=True)


@dataclasses.dataclass
class Provisioned:
    state: Path                       # swtpm state to copy for each case that boots this CC
    data: Path                        # CC data folder, as p2-unseal reads it
    disk: bytes                       # the same folder as a tar, padded for the data disk
    secrets_sha256: dict[str, str]
    record: dict
    # The keys themselves, in memory only, for TC-09 to search the TPM traffic. Never written anywhere.
    secrets: dict[str, bytes] = dataclasses.field(default_factory=dict, repr=False)


def tar_folder(folder: Path) -> bytes:
    """A reproducible tar of `folder`, padded to the data disk size."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in sorted(p for p in folder.rglob("*") if p.is_file()):
            info = tarfile.TarInfo(path.relative_to(folder).as_posix())
            info.size, info.mode, info.mtime = path.stat().st_size, 0o644, 0
            with path.open("rb") as f:
                tar.addfile(info, f)
    data = buf.getvalue()
    if len(data) > DATA_DISK_BYTES:
        raise ValueError("CC data does not fit the data disk")
    return data.ljust(DATA_DISK_BYTES, b"\0")


PARENT = f"{ap.PARENT_HANDLE:#x}"
EPOCH_NV = f"{ap.EPOCH_NV_INDEX:#x}"


def cc_objects(tpm: TcpSwtpm, wd: Path, parent_name: Path) -> tuple[str, int]:
    """The factory's TPM objects: the persistent parent and the epoch index (no bits set).

    Writes the parent's name to `parent_name`; returns the epoch index's name and attributes as the TPM reports them.
    """
    tpm.tpm2("createprimary", "-Q", "-C", "o", "-g", "sha256", "-G", "ecc256:aes128cfb", "-c", "primary.ctx", cwd=wd)
    tpm.tpm2("evictcontrol", "-Q", "-C", "o", "-c", "primary.ctx", PARENT, cwd=wd)
    tpm.tpm2("flushcontext", "-t", cwd=wd)   # swtpm has no resource manager
    tpm.tpm2("readpublic", "-Q", "-c", PARENT, "-n", str(parent_name), cwd=wd)
    tpm.tpm2("nvdefine", "-Q", EPOCH_NV, "-C", "o", "-s", str(ap.EPOCH_NV_SIZE), "-a", EPOCH_NV_ATTRIBUTES, cwd=wd)
    tpm.tpm2("nvsetbits", "-Q", EPOCH_NV, "-C", "o", "-i", "0", cwd=wd)
    nv_public = tpm.tpm2("nvreadpublic", EPOCH_NV, cwd=wd)
    return (re.search(r"name:\s*([0-9a-f]+)", nv_public).group(1),
            int(re.search(r"attributes:.*?value:\s*(0x[0-9a-fA-F]+)", nv_public, re.S).group(1), 16))


def provision(work: Path, short: Path, kpol_key: Path, pcrs: dict[int, str], epoch: int = 0) -> Provisioned:
    """Provision a fresh TPM and the CC data for a release with these predicted PCRs."""
    wd, data, secrets = work / "provision", work / "ccdata", short / "secrets"
    for d in (wd, data / "sealed", secrets):
        d.mkdir(parents=True, exist_ok=True)
    state = short / "tpm-provisioned"
    tpm = TcpSwtpm(state)

    def tpm2(*args: str) -> str:
        return tpm.tpm2(*args, cwd=wd)

    try:
        parent, nv = PARENT, EPOCH_NV
        nv_name_tpm, nv_attrs_tpm = cc_objects(tpm, wd, data / "parent.name")

        pem = subprocess.run(["openssl", "pkey", "-in", str(kpol_key), "-pubout"], check=True,
                             capture_output=True).stdout
        (wd / "kpol.pem").write_bytes(pem)
        tpm2("loadexternal", "-Q", "-C", "o", "-G", "ecc", "-u", "kpol.pem", "-c", "kpol.ctx", "-n", "kpol.name")
        tpm2("readpublic", "-Q", "-c", "kpol.ctx", "-o", str(data / "kpol.pub"))
        tpm2("flushcontext", "-t")
        kpol = ap.parse_public((data / "kpol.pub").read_bytes())
        seal_policy = ap.policy_authorize(kpol["name"])
        (wd / "seal-policy.bin").write_bytes(seal_policy)

        secrets_sha256, sealed, kept = {}, {}, {}
        for name in KEYS:
            secret = wireguard_key() if name == "wireguard" else os.urandom(32)
            (secrets / name).write_bytes(secret)
            secrets_sha256[name] = hashlib.sha256(secret).hexdigest()
            kept[name] = secret
            tpm2("create", "-Q", "-C", parent, "-L", str(wd / "seal-policy.bin"), "-a", SEALED_ATTRIBUTES,
                 "-i", str(secrets / name), "-u", str(data / f"sealed/{name}.pub"),
                 "-r", str(data / f"sealed/{name}.priv"))
            (secrets / name).unlink()
            pub = ap.parse_public((data / f"sealed/{name}.pub").read_bytes())
            sealed[name] = {"attributes": f"{pub['attributes']:#010x}",
                            "flags": sorted(f for f, bit in ap.TPMA_OBJECT.items() if pub["attributes"] & bit),
                            "auth_policy": pub["auth_policy"].hex(), "name": pub["name"].hex()}
    finally:
        tpm.stop()

    # The MSS approves this release (tools/approve_policy.py).
    approved = ap.approved_policy(pcrs, epoch)
    ap.write_policy(data, approved, ap.sign(kpol_key, approved), epoch)

    record = {
        "parent_handle": parent, "parent_name": (data / "parent.name").read_bytes().hex(),
        "epoch_nv_index": nv, "epoch_nv_attributes": {"tpm": f"{nv_attrs_tpm:#010x}",
                                                       "expected": f"{ap.EPOCH_NV_ATTRIBUTES:#010x}"},
        "epoch_nv_name": {"tpm": nv_name_tpm, "computed": ap.nv_name().hex()},
        "kpol_name": {"tpm": (wd / "kpol.name").read_bytes().hex(), "computed": kpol["name"].hex()},
        "policy_ref": ap.POLICY_REF.decode(), "seal_policy": seal_policy.hex(),
        "sealed_objects": sealed, "secrets_sha256": secrets_sha256,
        "epoch": epoch, "approved_policy": approved.hex(),
        "approved_for_pcrs_sha256": {str(i): pcrs[i] for i in ap.POLICY_PCRS},
    }
    return Provisioned(state, data, tar_folder(data), secrets_sha256, record, kept)


def provisioning_checks(prov: Provisioned) -> list[dict]:
    """Static checks that the provisioned objects are what docs/03 specifies."""
    r = prov.record
    checks = [
        {"kind": "provision", "pattern": "the epoch index name the MSS computes equals the name the TPM reports",
         "ok": r["epoch_nv_name"]["tpm"] == r["epoch_nv_name"]["computed"], "observed": r["epoch_nv_name"]},
        {"kind": "provision", "pattern": "the K-CC-POL name computed from its public area equals the TPM's",
         "ok": r["kpol_name"]["tpm"] == r["kpol_name"]["computed"], "observed": r["kpol_name"]},
    ]
    for name, obj in r["sealed_objects"].items():
        checks.append({"kind": "provision",
                       "pattern": f"{name}: fixedtpm, fixedparent and adminwithpolicy set; userwithauth clear",
                       "ok": obj["flags"] == ["adminwithpolicy", "fixedparent", "fixedtpm"], "observed": obj["flags"]})
        checks.append({"kind": "provision", "pattern": f"{name}: authPolicy is PolicyAuthorize(K-CC-POL, policyRef)",
                       "ok": obj["auth_policy"] == r["seal_policy"], "observed": obj["auth_policy"]})
    return checks


def copy_state(src: Path, dest: Path) -> Path:
    """A private copy of a provisioned TPM for one boot."""
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("*.log", ".lock"))
    return dest


def second_cc(work: Path, short: Path) -> tuple[Path, bytes]:
    """Another CC's TPM, provisioned the same way (TC-07). Its seeds, and so its parent, differ."""
    wd = work / "provision-second"
    wd.mkdir(parents=True, exist_ok=True)
    state = short / "tpm-second"
    tpm = TcpSwtpm(state)
    try:
        cc_objects(tpm, wd, wd / "parent.name")
    finally:
        tpm.stop()
    return state, (wd / "parent.name").read_bytes()


def commit_epoch(src: Path, dest: Path, epoch: int, wd: Path) -> Path:
    """A copy of the TPM at `src` after an update to `epoch` is committed: bit `epoch` set (section 3.5, step 4)."""
    copy_state(src, dest)
    wd.mkdir(parents=True, exist_ok=True)
    tpm = TcpSwtpm(dest)
    try:
        tpm.tpm2("nvsetbits", "-Q", EPOCH_NV, "-C", "o", "-i", f"{1 << epoch:#x}", cwd=wd)
    finally:
        tpm.stop()
    return dest


def data_variant(prov: Provisioned, folder: Path, files: dict[str, bytes]) -> bytes:
    """The provisioned CC data with some files replaced, packed for a data disk."""
    shutil.rmtree(folder, ignore_errors=True)
    shutil.copytree(prov.data, folder)
    for rel, content in files.items():
        (folder / rel).write_bytes(content)
    return tar_folder(folder)
