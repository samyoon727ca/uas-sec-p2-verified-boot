#!/usr/bin/env python3
"""Build and sign the approved policy that releases the CC's sealed keys (docs/03 sections 3.2 to 3.4).

The MSS runs this for each release. From the release artifacts it predicts
PCRs 0, 1, 8 and 9 (tools/predict_pcrs.py), then builds the approved policy

    PolicyPCR(sha256: 0, 1, 8, 9 = predicted values)
    PolicyNV (epoch index, operandB = bits above E, offset 0, TPM_EO_BITCLEAR)

and signs it with K-CC-POL for TPM2_PolicyAuthorize: an ECDSA P-256
signature over SHA-256(approvedPolicy || policyRef). The sealed objects carry
PolicyAuthorize(K-CC-POL, policyRef) as their authPolicy, so any policy the
MSS signs for this policyRef can release them, and nothing else can.

Policy digests are computed here, offline, as the TPM computes them (TPM 2.0
Library Part 3: PolicyPCR, PolicyNV, PolicyAuthorize); the unit tests check
them against values tpm2-tools 5.6 produced in trial sessions. Signing uses
the openssl command line.

Usage:
    python3 tools/approve_policy.py --fit cc.itb --uboot u-boot.bin --epoch 0 \\
        --key k-cc-pol.pem --out ccdata/

writes ccdata/policy/approved (32 bytes), approved.sig (TPMT_SIGNATURE) and
epoch, the files the CC's unseal agent reads (cc/initramfs/p2-unseal.c).
Standard library and openssl only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import predict_pcrs  # noqa: E402

# Shared with cc/initramfs/p2-unseal.c and the VE-07 provisioning; a unit test keeps them equal.
PARENT_HANDLE = 0x81000001     # persistent ECC P-256 storage key; also salts the unseal session
EPOCH_NV_INDEX = 0x01000001    # TPM_NT_BITS anti-rollback epoch (SR-010.3)
POLICY_REF = b"p2/cc-keys"     # names this use of K-CC-POL (section 3.2)
POLICY_PCRS = predict_pcrs.POLICY_PCRS

TPM_ALG_SHA256 = 0x000B
TPM_ALG_ECDSA = 0x0018
TPM_CC_POLICY_NV = 0x00000149
TPM_CC_POLICY_AUTHORIZE = 0x0000016A
TPM_CC_POLICY_PCR = 0x0000017F
TPM_EO_BITCLEAR = 0x000B

# TPMA_NV of the epoch index once provisioned: TPM_NT_BITS, written with owner
# authorization, read with its empty authValue, no dictionary-attack lockout.
TPMA_NV_OWNERWRITE = 1 << 1
TPM_NT_BITS = 0x2 << 4
TPMA_NV_AUTHREAD = 1 << 18
TPMA_NV_NO_DA = 1 << 25
TPMA_NV_WRITTEN = 1 << 29
EPOCH_NV_ATTRIBUTES = TPMA_NV_OWNERWRITE | TPM_NT_BITS | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA | TPMA_NV_WRITTEN
EPOCH_NV_SIZE = 8

# TPMA_OBJECT bits checked on the sealed objects (section 3.2).
TPMA_OBJECT = {"fixedtpm": 1 << 1, "fixedparent": 1 << 4, "sensitivedataorigin": 1 << 5,
               "userwithauth": 1 << 6, "adminwithpolicy": 1 << 7}


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- names ----------------------------------------------------------------------

def nv_name(index: int = EPOCH_NV_INDEX, attributes: int = EPOCH_NV_ATTRIBUTES, size: int = EPOCH_NV_SIZE,
            auth_policy: bytes = b"") -> bytes:
    """Name of an NV index: nameAlg || H(TPMS_NV_PUBLIC). It is the same on every CC."""
    public = struct.pack(">IHIH", index, TPM_ALG_SHA256, attributes, len(auth_policy)) + auth_policy + \
        struct.pack(">H", size)
    return struct.pack(">H", TPM_ALG_SHA256) + h(public)


def parse_public(tpm2b: bytes) -> dict:
    """The leading fields of a marshaled TPM2B_PUBLIC, and the object's name."""
    (size,) = struct.unpack_from(">H", tpm2b, 0)
    area = tpm2b[2:2 + size]
    if size < 10 or len(area) != size:
        raise ValueError("not a TPM2B_PUBLIC")
    obj_type, name_alg, attributes, policy_size = struct.unpack_from(">HHIH", area, 0)
    if name_alg != TPM_ALG_SHA256:
        raise ValueError(f"name algorithm {name_alg:#x} is not SHA-256")
    return {"type": obj_type, "name_alg": name_alg, "attributes": attributes,
            "auth_policy": area[10:10 + policy_size], "name": struct.pack(">H", name_alg) + h(area)}


# --- policy digests --------------------------------------------------------------

def pcr_selection(pcrs=POLICY_PCRS) -> bytes:
    """TPML_PCR_SELECTION with one SHA-256 bank selecting `pcrs`."""
    bitmap = bytearray(3)
    for i in pcrs:
        bitmap[i // 8] |= 1 << (i % 8)
    return struct.pack(">IHB", 1, TPM_ALG_SHA256, 3) + bytes(bitmap)


def policy_pcr(old: bytes, values: dict[int, str], pcrs=POLICY_PCRS) -> bytes:
    pcr_digest = h(b"".join(bytes.fromhex(values[i]) for i in sorted(pcrs)))
    return h(old + struct.pack(">I", TPM_CC_POLICY_PCR) + pcr_selection(pcrs) + pcr_digest)


def policy_nv(old: bytes, operand: bytes, offset: int, operation: int, index_name: bytes) -> bytes:
    args = h(operand + struct.pack(">HH", offset, operation))
    return h(old + struct.pack(">I", TPM_CC_POLICY_NV) + args + index_name)


def policy_authorize(key_name: bytes, policy_ref: bytes = POLICY_REF) -> bytes:
    """The sealed objects' authPolicy: PolicyAuthorize from a fresh session."""
    return h(h(bytes(32) + struct.pack(">I", TPM_CC_POLICY_AUTHORIZE) + key_name) + policy_ref)


def epoch_operand(epoch: int) -> bytes:
    """operandB for epoch E: every bit above E set. BITCLEAR then passes only if none of them is set in the TPM."""
    if not 0 <= epoch <= 63:
        raise ValueError("epoch must be 0 to 63")
    return struct.pack(">Q", ~((1 << (epoch + 1)) - 1) & (2 ** 64 - 1))


def approved_policy(pcrs: dict[int, str], epoch: int, index_name: bytes | None = None) -> bytes:
    digest = policy_pcr(bytes(32), pcrs)
    return policy_nv(digest, epoch_operand(epoch), 0, TPM_EO_BITCLEAR, index_name or nv_name())


# --- signature --------------------------------------------------------------------

def der_to_tpmt_signature(der: bytes) -> bytes:
    """An OpenSSL ECDSA signature (DER SEQUENCE of r, s) as a marshaled TPMT_SIGNATURE."""
    def read(tag: int, pos: int) -> tuple[bytes, int]:
        if der[pos] != tag or der[pos + 1] & 0x80:
            raise ValueError("unexpected DER encoding")
        length = der[pos + 1]
        return der[pos + 2:pos + 2 + length], pos + 2 + length

    body, end = read(0x30, 0)
    if end != len(der):
        raise ValueError("trailing bytes after the DER signature")
    r, pos = read(0x02, 2)
    s, pos = read(0x02, pos)
    if pos != end:
        raise ValueError("unexpected DER encoding")
    r, s = r.lstrip(b"\0").rjust(32, b"\0"), s.lstrip(b"\0").rjust(32, b"\0")
    if len(r) != 32 or len(s) != 32:
        raise ValueError("not a P-256 signature")
    return struct.pack(">HHH", TPM_ALG_ECDSA, TPM_ALG_SHA256, 32) + r + struct.pack(">H", 32) + s


def sign(key: Path, approved: bytes, policy_ref: bytes = POLICY_REF) -> bytes:
    """Sign approvedPolicy || policyRef with K-CC-POL; returns a TPMT_SIGNATURE."""
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)], input=approved + policy_ref,
                         capture_output=True, check=True).stdout
    return der_to_tpmt_signature(der)


def write_policy(out: Path, approved: bytes, signature: bytes, epoch: int) -> None:
    (out / "policy").mkdir(parents=True, exist_ok=True)
    (out / "policy/approved").write_bytes(approved)
    (out / "policy/approved.sig").write_bytes(signature)
    (out / "policy/epoch").write_text(f"{epoch}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fit", type=Path, required=True, help="signed FIT of the release")
    parser.add_argument("--uboot", type=Path, required=True, help="U-Boot binary of the release")
    parser.add_argument("--epoch", type=int, required=True, help="anti-rollback epoch of the release (0 to 63)")
    parser.add_argument("--key", type=Path, required=True, help="K-CC-POL private key (PEM, ECDSA P-256)")
    parser.add_argument("--out", type=Path, required=True, help="CC data folder; policy/ is written inside it")
    args = parser.parse_args(argv)

    pred = predict_pcrs.predict(args.fit.read_bytes(), args.uboot.read_bytes())
    approved = approved_policy(pred.pcrs, args.epoch)
    write_policy(args.out, approved, sign(args.key, approved), args.epoch)
    print(json.dumps({"epoch": args.epoch, "approved_policy": approved.hex(),
                      "pcrs_sha256": {str(i): pred.pcrs[i] for i in POLICY_PCRS}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
