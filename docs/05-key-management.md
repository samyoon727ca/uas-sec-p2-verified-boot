# 5. Key management

P2 uses five signing keys, all dev/test keys. CI generates a fresh set on every run and discards it. Keys for hardware runs are generated on the owner's machine and kept in a git-ignored `keys/` folder. No private key is ever committed: `tools/check_no_secrets.py` fails CI if one appears.

P3 takes custody with an offline root tier and an HSM-held intermediate tier. None of the devices checks an X.509 chain; each trusts a raw public key or its hash. So the hand-off to P3 is about custody and ceremony; P3's certificates record each key's purpose and are not checked by any device.

## 5.1 Keys

| Key | Algorithm | Security strength | Trusted by | Signs | P2 custody | P3 custody | Rotation |
|---|---|---|---|---|---|---|---|
| K-CC-ROOT | RSA-2048, PKCS#1 v1.5 (fixed by the Pi boot loader [RPI-SB]) | 112 bits | Raspberry Pi boot loader; key hash in OTP | `boot.img` (Pi firmware, U-Boot, U-Boot devicetree) | Generated offline for the hardware phase; encrypted backup | Offline root tier | **Never.** OTP cannot be reprogrammed |
| K-CC-OS | RSA-3072 with SHA-256 | 128 bits | U-Boot: public key in its control devicetree, marked required | FIT configurations | CI: per run. Hardware: local | HSM intermediate tier; U-Boot's `mkimage -N` signs through an OpenSSL PKCS#11 engine [UBOOT-SIG] | Ship a new `boot.img` carrying the new public key |
| K-CC-POL | ECDSA P-256 with SHA-256 | 128 bits | TPM: the key's name is bound into each sealed object's policy | Approved PCR policies (§3.3) | CI: per run. Hardware: local | HSM intermediate tier | Re-provision: the name is fixed in the sealed objects' policy |
| K-FC-FW | Ed25519 (fixed by PX4) | — | PX4 boot loader, keystore slot 0 | PX4 firmware | Local, git-ignored | HSM intermediate tier, once a PKCS#11 Ed25519 signer exists (OI2-04) | Reflash the boot loader over SWD |
| K-FC-REC | Ed25519 | — | PX4 boot loader, keystore slot 1 | Recovery firmware only | Offline | Offline root tier | Reflash the boot loader over SWD |

Security strengths are from NIST SP 800-57 Part 1 Rev. 5, Table 2 [SP800-57]. Ed25519 is not given a strength here: its group order is 253 bits, which falls in that table's 112-bit row, while it is commonly described as 128-bit.

**K-CC-ROOT is the long-term weakness.** Under SP 800-57 Table 4, 112-bit strength is acceptable for applying protection through 2030, is disallowed from 2031, and allows only legacy processing after that [SP800-57]. The Pi boot loader fixes RSA-2048, and OTP fixes the key, so a Pi-based CC cannot follow that transition. A fielded design would need a SoC whose root of trust supports 128-bit keys. This is recorded for P1 and P6.

The TPM's own keys (the sealing parent and the salt key) are generated inside the TPM and never leave it. They are not signing keys and are not listed here.

## 5.2 Dev-key rules

1. **Never committed.** `.gitignore` excludes `keys/` and common key file names. `tools/check_no_secrets.py` scans every tracked and untracked, non-ignored file for PEM, OpenSSH and TSS private keys and for PX4 key files.
2. **Per run in CI.** Test harnesses generate keys in a temporary directory and delete it. Evidence records each public key's SHA-256, never a private key.
3. **Labeled.** Dev public keys are named `*-dev`. Nothing signed with a dev key is presented as a release.
4. **The PX4 test key** in the PX4 tree is public. P2 uses it only as the wrong-key case (TC-13).
5. **OTP is not programmed with a dev key** without the owner's explicit go-ahead at that moment (OI2-02).

## 5.3 Hand-off to P3

| P2 artifact | What P3 does |
|---|---|
| Key table (§5.1), with algorithms fixed by each verifier | Generates production keys in the HSM or offline tier to match. Issues a purpose-bound certificate for each public key for inventory and audit |
| Signing commands: `mkimage -k` for FIT, `openssl dgst -sign` for policies, `sign_firmware.py` for PX4 | Swaps each file-based signer for an HSM signer: `mkimage -N pkcs11`; a PKCS#11 ECDSA signer for policies; a PKCS#11 Ed25519 signer for PX4 (OI2-04) |
| Epoch-commit authorization (OI2-05) | Defines an MSS-signed authorization that lets a CC advance its epoch with no stored secret |
| Signed approved policy shipped with each CC release | Includes it in the signed update metadata (SR-007) |
