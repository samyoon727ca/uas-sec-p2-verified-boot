#!/usr/bin/env python3
"""Check a planned i.MX 8M Plus HAB fuse burn against the SRK table before anything is burned (OI2-02).

TC-02 needs two permanent fuse steps (docs/02 section 2.2). [NXP-FUSE] burns
the SRK hash into bank 6 words 0-3 and bank 7 words 0-3, then closes the chip
with "fuse prog 1 3 0x2000000" (SEC_CONFIG[1]). On a closed chip, "an error in
SRK Hash results in a part that does not boot" [UBOOT-HAB]. So this tool
computes the fuse words from the SRK table, renders the eight SRK commands,
and checks a planned command file against them. It works only on the bytes
and text it is given: it never opens a device, serial port or network
connection. Standard library only.

    python tools/fuse_preflight.py --srk-table T --flash-bin F --uboot-itb U --plan P
        [--dev-inventory I] [--dev-board] [--hab-log L] [--recovery-evidence E] --out DIR

runs every check, prints every finding and exits 1 if any blocks, writing
nothing. Otherwise it writes DIR/fuse-burn-record.md and .json (keys in
main's docstring): the commands the owner types at TC-02, Step A the SRK
hash and Step B, only for a plan that closes the chip, the close command.

The hash burned must be the hash of the SRK table CST put in each signed
image, so the tool also reads that table out of flash.bin and u-boot.itb.
The layout comes from [UBOOT-HAB] mx8m_spl_secure_boot.txt and the
binman signer it describes (tools/binman/etype/nxp_imx8mcst.py) [UBOOT]:
- flash.bin is the signed SPL part, then the signed FIT part. The SPL part
  is an IVT loaded at CONFIG_SPL_TEXT_BASE - 0x40, boot data, padding to
  0x40, SPL and DDR firmware, then the CSF at the IVT's csf pointer.
- The FIT part, a signed u-boot.itb, is the FIT padded to 4 KiB, then an
  IVT, then the CSF (csf = self + 0x20).
- An IVT is a HAB header (tag 0xD1, length 0x0020, version 0x4n), then
  seven little-endian words: entry, reserved, dcd, boot_data, self, csf,
  reserved. self is the IVT's own load address, so address A lies at file
  offset ivt_offset + A - self.
Neither guide gives the CSF layout. It is HABv4's, as NXP's SPSDK reads and
writes it (commit e104adf5, spsdk/image/hab/: commands/cmd_install_key.py,
segments/seg_csf.py):
- A CSF is a HAB header (tag 0xD4, length of header and commands, version
  0x4n), then commands, each a HAB header (tag, length of the whole
  command, flags) and its fields. Key data such as the SRK table follows
  the commands (introduction_habv4.txt: the CSF "contains the commands,
  SRK table, signatures and certificates").
- Install SRK is an Install Key command (tag 0xBE) whose protocol byte is
  0x03 (SRK). Its fields are protocol, hash algorithm, source index (the
  SRK index) and target index, one byte each, then a big-endian word: the
  SRK table's offset from the CSF start. Flag 0x01 makes it an absolute
  address instead, which SPSDK uses only for DEK keys, so it is refused.
Every IVT header found is taken as an IVT and must lead to a valid CSF.
A stray match in a payload refuses the image rather than being skipped.
None of this has been checked against a real CST-signed image yet.

Three gates come before any burn (docs/05 rule 5, OI2-02, OI2-07):
- Dev-key inventory: lines of "<sha256-hex> <label>", "#" comments and blank
  lines allowed. The hash is an SRK fuse hash or the SHA-256 of one SRK table
  key entry (header included); every label must end in "-dev". It holds
  hashes only, never key material. A match is a finding, or only a warning
  naming the label when the burn is for a dev board.
- HAB log: a U-Boot "hab_status" console capture, which the owner heads with
  "# flash.bin sha256: <hex>" and "# u-boot.itb sha256: <hex>" for the images
  booted. It is clean only with "No HAB Events Found!", no "HAB Event N"
  block, and both digests equal to the images checked.
- Close gate: any fuse write needs --recovery-evidence, a file under
  evidence/ listed with its hash in evidence/SHA256SUMS: the confirmed
  recovery run (OI2-07). Writing bank 1 word 3 (closing the chip) also needs
  a clean HAB log for these images (OI2-02).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

import check_evidence

HAB_HEADER = struct.Struct(">BHB")  # tag, length of the whole structure (big-endian), version or algorithm
HAB_TAG_SRK_TABLE = 0xD7
HAB_TAG_PUBLIC_KEY = 0xE1
MAX_SRKS = 4
IVT_HEADER = b"\xd1\x00\x20"        # tag 0xD1, length 0x0020; a version byte 0x40 to 0x4F follows
IVT = struct.Struct("<4x7I")        # after the header: entry, reserved, dcd, boot_data, self, csf, reserved
HAB_TAG_CSF = 0xD4
HAB_CMD_INSTALL_KEY = 0xBE
INSTALL_KEY = struct.Struct(">4x4BI")   # after the header: protocol, hash algorithm, source, target, key location
HAB_PCL_SRK = 0x03
HAB_INSTALL_KEY_ABSOLUTE = 0x01

# [NXP-FUSE] sections 1.7 and 1.9, i.MX 8M family: the SRK hash words in this order, then the close fuse.
SRK_FUSES = ((6, 0), (6, 1), (6, 2), (6, 3), (7, 0), (7, 1), (7, 2), (7, 3))
CLOSE_FUSE = (1, 3)
CLOSE_VALUE = 0x2000000     # SEC_CONFIG[1]

# [UBOOT] cmd/fuse.c reads bank and word with base 0 (a leading zero means octal), and each value as hex with no
# error check, cut to 32 bits; further values go to the following words. So a plan line takes bank and word in
# decimal without leading zeros, and one 0x-prefixed value of at most 8 hex digits.
PLAN_LINE = re.compile(r"fuse[ \t]+prog[ \t]+(?:(-y)[ \t]+)?(0|[1-9][0-9]*)[ \t]+(0|[1-9][0-9]*)[ \t]+"
                       r"0x([0-9a-fA-F]{1,8})")


class PreflightError(Exception):
    """An input that cannot be checked: the message says which and where."""


@dataclasses.dataclass(frozen=True)
class SrkTable:
    version: int
    keys: tuple[bytes, ...]     # each public-key entry whole, its HAB header included


@dataclasses.dataclass(frozen=True)
class Ivt:
    offset: int                 # in the file
    version: int
    entry: int
    dcd: int
    boot_data: int
    self_addr: int              # the IVT's "self" field: the address the IVT is loaded at
    csf: int

    def file_offset(self, address: int) -> int:
        """Where a load address of this IVT's image lies in the file, which may be outside it."""
        return self.offset + address - self.self_addr


@dataclasses.dataclass(frozen=True)
class FuseWrite:
    line: int                   # in the plan, from 1
    bank: int
    word: int
    value: int
    confirmed: bool             # "-y": U-Boot writes without asking


@dataclasses.dataclass(frozen=True)
class Finding:
    kind: str
    message: str
    error: bool = True          # False only for "close step" and for "dev key" on a dev board: warnings


def hexword(value: int) -> str:
    return f"0x{value:08X}"


# --- SRK table and hash ----------------------------------------------------------

def parse_srk_table(data: bytes) -> SrkTable:
    """Split a HABv4 SRK table (CST's SRK_1_2_3_4_table.bin) into its key entries: a HAB header (tag 0xD7,
    big-endian length of the whole table, version 0x4n), then one to four public-key entries, each with its own
    HAB header (tag 0xE1, big-endian length of the entry, algorithm)."""
    if len(data) < HAB_HEADER.size:
        raise PreflightError(f"SRK table: {len(data)} bytes, too short for its {HAB_HEADER.size}-byte HAB header")
    tag, length, version = HAB_HEADER.unpack_from(data)
    if tag != HAB_TAG_SRK_TABLE:
        raise PreflightError(f"SRK table: header tag {tag:#04x}, expected {HAB_TAG_SRK_TABLE:#04x}")
    if version >> 4 != 4:
        raise PreflightError(f"SRK table: version {version:#04x} is not HABv4 (0x4n)")
    if length < HAB_HEADER.size or length > len(data):
        raise PreflightError(f"SRK table: length mismatch: header says {length} bytes, the data has {len(data)}")
    if length < len(data):
        raise PreflightError(f"SRK table: {len(data) - length} trailing bytes after the {length}-byte table")
    keys, pos = [], HAB_HEADER.size
    while pos < length:
        where = f"SRK table: entry {len(keys) + 1} at offset {pos}"
        if length - pos < HAB_HEADER.size:
            raise PreflightError(f"{where}: {length - pos} bytes left, too short for a key header")
        tag, size, _ = HAB_HEADER.unpack_from(data, pos)
        if tag != HAB_TAG_PUBLIC_KEY:
            raise PreflightError(f"{where}: tag {tag:#04x}, expected {HAB_TAG_PUBLIC_KEY:#04x} (public key)")
        if not HAB_HEADER.size < size <= length - pos:
            raise PreflightError(f"{where}: length mismatch: entry says {size} bytes, "
                                 f"expected {HAB_HEADER.size + 1} to the {length - pos} left in the table")
        keys.append(data[pos:pos + size])
        pos += size
    if not 1 <= len(keys) <= MAX_SRKS:
        raise PreflightError(f"SRK table: {len(keys)} key entries, expected 1 to {MAX_SRKS}")
    return SrkTable(version, tuple(keys))


def srk_fuse_hash(data: bytes) -> bytes:
    """The 32 bytes that go into the SRK hash fuses for this SRK table.

    This is the value CST's srktool writes to SRK_1_2_3_4_fuse.bin [NXP-CST],
    the file whose words [NXP-FUSE] burns into bank 6 words 0 to 3 and bank 7
    words 0 to 3. HABv4 does not hash the table as a whole: it hashes a table
    of key hashes, SHA-256 over the concatenated SHA-256 of each key entry,
    header included. This is computed from the format alone; the independent
    check against NXP's SPSDK comes in the next task.
    """
    table = parse_srk_table(data)
    return hashlib.sha256(b"".join(hashlib.sha256(key).digest() for key in table.keys)).digest()


def fuse_words(digest: bytes) -> list[int]:
    """The eight 32-bit fuse words of an SRK hash, in SRK_FUSES order. Each is a little-endian read of 4 bytes,
    as [NXP-FUSE]'s hexdump -e '/4 "0x"' -e '/4 "%X""\\n"' SRK_1_2_3_4_fuse.bin prints them on the host."""
    if len(digest) != 32:
        raise PreflightError(f"SRK hash: {len(digest)} bytes, expected 32")
    return list(struct.unpack("<8I", digest))


def render_srk_commands(words: list[int]) -> list[str]:
    """The eight U-Boot commands that burn the SRK hash: bank 6 words 0 to 3, then bank 7 words 0 to 3 [NXP-FUSE]."""
    if len(words) != len(SRK_FUSES) or not all(0 <= w <= 0xFFFFFFFF for w in words):
        raise PreflightError(f"SRK hash: expected {len(SRK_FUSES)} words of 32 bits, got {words!r}")
    # Without "-y", as in [NXP-FUSE]: U-Boot asks before each permanent write, so the go-ahead docs/05 rule 5
    # requires is given at the console. Values print as the guide's hexdump prints them: uppercase, no padding.
    return [f"fuse prog {bank} {word} 0x{value:X}" for (bank, word), value in zip(SRK_FUSES, words)]


# --- fuse plan -------------------------------------------------------------------

def parse_fuse_plan(text: str) -> list[FuseWrite]:
    """Read a planned fuse-command file: one "fuse prog [-y] <bank> <word> 0x<hex>" per line, "#" comments and
    blank lines allowed. Any other command, and any fuse prog line in another form, is refused."""
    plan = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.split()[:2] != ["fuse", "prog"]:
            raise PreflightError(f"plan line {number}: not a fuse prog command: {line!r}")
        match = PLAN_LINE.fullmatch(line)
        if not match:
            raise PreflightError(f"plan line {number}: malformed, expected "
                                 f"'fuse prog [-y] <bank> <word> 0x<hex>', got {line!r}")
        plan.append(FuseWrite(number, int(match[2]), int(match[3]), int(match[4], 16), match[1] is not None))
    return plan


def check_plan(plan: list[FuseWrite], digest: bytes) -> list[Finding]:
    """Check a parsed fuse plan against the SRK hash it is meant to burn: findings in plan order, then any SRK word
    the plan leaves out. The plan may run only if none is an error. A correct close command is still reported, as
    its own step: closing the chip is a second permanent step with its own go-ahead (docs/05 rule 5)."""
    expected = dict(zip(SRK_FUSES, fuse_words(digest)))
    srk_lines = [w.line for w in plan if (w.bank, w.word) in expected]
    findings = []
    for w in plan:
        at = f"line {w.line}: bank {w.bank} word {w.word}"
        got = hexword(w.value)
        if (w.bank, w.word) in expected:
            want = expected[(w.bank, w.word)]
            if w.value == want:
                continue
            other = next((pos for pos, value in expected.items() if value == w.value), None)
            if other is not None:
                findings.append(Finding("word swap", f"{at}: word swap: expected {hexword(want)}, got {got}, "
                                                     f"the word for bank {other[0]} word {other[1]}"))
            elif w.value == int.from_bytes(want.to_bytes(4, "little"), "big"):
                findings.append(Finding("byte swap", f"{at}: byte swap: expected {hexword(want)}, got {got}, "
                                                     "its bytes reversed"))
            else:
                findings.append(Finding("mismatch", f"{at}: mismatch: expected {hexword(want)}, got {got}"))
        elif (w.bank, w.word) == CLOSE_FUSE:
            if w.value != CLOSE_VALUE:
                findings.append(Finding("close value", f"{at}: close command refused: "
                                                       f"expected {hexword(CLOSE_VALUE)}, got {got}"))
            else:
                findings.append(Finding("close step", f"{at}: closes the chip (SEC_CONFIG[1]), a separate "
                                                      "permanent step after the SRK hash, with its own go-ahead",
                                        error=False))
            if srk_lines and w.line < max(srk_lines):
                findings.append(Finding("close order", f"{at}: close command before the SRK hash is complete: "
                                                       f"expected after line {max(srk_lines)}, got line {w.line}"))
        else:
            findings.append(Finding("unknown fuse write", f"{at}: unknown fuse write: expected none outside "
                                                          f"bank 6/7 words 0-3 and bank 1 word 3, got {got}"))
    written = {(w.bank, w.word) for w in plan}
    for (bank, word), want in expected.items():
        if (bank, word) not in written:
            findings.append(Finding("missing", f"bank {bank} word {word}: SRK hash word missing: "
                                               f"expected {hexword(want)}, got no write"))
    return findings


# --- signed images ---------------------------------------------------------------

def find_ivts(image: bytes) -> list[Ivt]:
    """Every IVT in an image, at any offset: a HAB header with tag 0xD1, length 0x0020 and version 0x40 to 0x4F,
    then its seven words. A header too near the end of the image to hold a whole IVT is refused."""
    ivts, pos = [], image.find(IVT_HEADER)
    while pos >= 0:
        if pos + 3 < len(image) and image[pos + 3] >> 4 == 4:
            if len(image) - pos < IVT.size:
                raise PreflightError(f"IVT at offset {pos:#x}: truncated: {len(image) - pos} bytes left, "
                                     f"expected {IVT.size}")
            entry, _, dcd, boot_data, self_addr, csf, _ = IVT.unpack_from(image, pos)
            ivts.append(Ivt(pos, image[pos + 3], entry, dcd, boot_data, self_addr, csf))
        pos = image.find(IVT_HEADER, pos + 1)
    return ivts


def parse_csf(blob: bytes) -> tuple[int, int]:
    """Walk the HAB commands of the CSF at the start of blob. Return its Install SRK command's SRK index and the
    SRK table's offset from the CSF start, which may be outside blob. Exactly one Install SRK is accepted."""
    if len(blob) < HAB_HEADER.size:
        raise PreflightError(f"CSF: {len(blob)} bytes, too short for its {HAB_HEADER.size}-byte HAB header")
    tag, length, version = HAB_HEADER.unpack_from(blob)
    if tag != HAB_TAG_CSF:
        raise PreflightError(f"CSF: header tag {tag:#04x}, expected {HAB_TAG_CSF:#04x}")
    if version >> 4 != 4:
        raise PreflightError(f"CSF: version {version:#04x} is not HABv4 (0x4n)")
    if not HAB_HEADER.size <= length <= len(blob):
        raise PreflightError(f"CSF: length mismatch: header says {length} bytes, only {len(blob)} left in the file")
    found, pos = [], HAB_HEADER.size
    while pos < length:
        where = f"CSF: command at offset {pos}"
        if length - pos < HAB_HEADER.size:
            raise PreflightError(f"{where}: {length - pos} bytes left, too short for a command header")
        tag, size, flags = HAB_HEADER.unpack_from(blob, pos)
        if not HAB_HEADER.size <= size <= length - pos:
            raise PreflightError(f"{where}: length mismatch: command says {size} bytes, "
                                 f"expected {HAB_HEADER.size} to the {length - pos} left in the CSF")
        if tag == HAB_CMD_INSTALL_KEY:
            if size < INSTALL_KEY.size:
                raise PreflightError(f"{where}: Install Key of {size} bytes, expected at least {INSTALL_KEY.size}")
            protocol, _, index, _, location = INSTALL_KEY.unpack_from(blob, pos)
            if protocol == HAB_PCL_SRK:
                if flags & HAB_INSTALL_KEY_ABSOLUTE:
                    raise PreflightError(f"{where}: Install SRK flags {flags:#04x} give an absolute address, "
                                         "expected an offset from the CSF")
                found.append((index, location))
        pos += size
    if not found:
        raise PreflightError("CSF: no Install SRK command (Install Key, tag 0xbe, protocol 0x03)")
    if len(found) > 1:
        raise PreflightError(f"CSF: {len(found)} Install SRK commands, expected 1")
    return found[0]


def _srk_in(image: bytes) -> list[tuple[int, bytes, int]]:
    ivts = find_ivts(image)
    if not ivts:
        raise PreflightError("no IVT (tag 0xd1, length 0x0020, version 0x4n): not a HAB-signed image")
    found = []
    for ivt in ivts:
        where = f"IVT at offset {ivt.offset:#x}"
        if ivt.csf == 0:
            raise PreflightError(f"{where}: no CSF: its csf pointer is 0, so the image is not signed")
        start = ivt.file_offset(ivt.csf)
        if not 0 <= start < len(image):
            raise PreflightError(f"{where}: CSF pointer {ivt.csf:#010x} is outside the file: "
                                 f"offset {start:#x}, the file has {len(image):#x} bytes")
        blob = image[start:]
        try:
            index, at = parse_csf(blob)
            if len(blob) - at < HAB_HEADER.size:
                raise PreflightError(f"SRK table offset {at:#x} is outside the file: "
                                     f"{len(blob):#x} bytes from the CSF to the end")
            table = blob[at:at + HAB_HEADER.unpack_from(blob, at)[1]]
            keys = parse_srk_table(table).keys
        except PreflightError as e:
            raise PreflightError(f"{where}: CSF at offset {start:#x}: {e}") from None
        if index >= len(keys):
            raise PreflightError(f"{where}: SRK index {index} is not in the SRK table: expected 0 to {len(keys) - 1}")
        found.append((ivt.offset, table, index))
    first = found[0]
    for other in found[1:]:
        if other[1:] != first[1:]:
            what = "SRK tables" if other[1] != first[1] else f"SRK indexes {first[2]} and {other[2]}"
            raise PreflightError(f"IVTs at offsets {first[0]:#x} and {other[0]:#x} disagree: their CSFs install "
                                 f"different {what}")
    return found


def extract_srk(image_path: str | Path) -> list[tuple[int, bytes, int]]:
    """The SRK table and SRK index each IVT's CSF installs in a signed flash.bin or u-boot.itb, as
    (IVT offset, SRK table bytes, SRK index) in file order. Refused: no IVT, an IVT with no CSF, a CSF with no
    Install SRK, a pointer or offset outside the file, an SRK index outside its table, and CSFs that disagree."""
    try:
        return _srk_in(Path(image_path).read_bytes())
    except OSError as e:
        raise PreflightError(f"{image_path}: cannot read: {e.strerror}") from None
    except PreflightError as e:
        raise PreflightError(f"{image_path}: {e}") from None


# SRK revocation. [NXP-FUSE] (mx8m_secure_boot.txt) gives only the SRK hash fuses and the close fuse, and
# [UBOOT-HAB] (mx8m_spl_secure_boot.txt, which defers to mx6_mx7_secure_boot.txt section 1.5 for fuses) gives
# only the SRK hash fuses. Neither says where SRK_REVOKE is on the i.MX 8M Plus or which bit revokes which SRK.
# So this tool does not guess: any plan write outside the SRK hash and close fuses is a finding, as it may revoke
# the SRK index the images' CSFs install.
def check_images(images: dict[str, list[tuple[int, bytes, int]]], digest: bytes,
                 plan: list[FuseWrite]) -> list[Finding]:
    """Check what extract_srk found in each image, by image name, against the SRK hash to burn and the fuse plan:
    every SRK table must hash to digest, and no plan write may revoke an SRK index the images use."""
    findings = []
    if not any(images.values()):
        findings.append(Finding("no image", "images: no signed image: expected the SRK table of at least one, "
                                            "got none"))
    for name, found in images.items():
        for offset, table, _ in found:
            got = srk_fuse_hash(table)
            if got != digest:
                findings.append(Finding("table mismatch", f"{name}: IVT at offset {offset:#x}: SRK table mismatch: "
                                                          f"expected hash {digest.hex()}, got {got.hex()}"))
    indexes = ", ".join(map(str, sorted({index for found in images.values() for _, _, index in found})))
    for w in plan:
        if (w.bank, w.word) not in SRK_FUSES and (w.bank, w.word) != CLOSE_FUSE:
            findings.append(Finding("revocation unchecked", f"line {w.line}: bank {w.bank} word {w.word}: revocation "
                                    f"unchecked: expected no write that may revoke SRK index {indexes}, got "
                                    f"{hexword(w.value)}; neither guide states where SRK_REVOKE is"))
    return findings


# --- gates: dev keys, HAB log, close ---------------------------------------------

SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
HAB_LOG_IMAGES = ("flash.bin", "u-boot.itb")
HAB_LOG_DIGEST = re.compile(r"#[ \t]*(flash\.bin|u-boot\.itb)[ \t]+sha256:[ \t]*(\S*)[ \t]*")  # HAB_LOG_IMAGES
HAB_LOG_EVENT = re.compile(r"\bHAB Event (\d+)\b")
HAB_LOG_CLEAN = "No HAB Events Found!"


@dataclasses.dataclass(frozen=True)
class HabLog:
    digests: dict[str, str]     # image name to lowercase SHA-256 hex, from the "# <image> sha256:" headers
    clean: bool                 # "No HAB Events Found!" and no event block
    events: tuple[str, ...]     # each "HAB Event N" block's text, its header line included


def parse_dev_inventory(text: str) -> dict[bytes, str]:
    """Read a dev-key inventory (format in the module docstring) into hash to label. Refused: a line that is not
    a 64-digit hex hash and one label, a label not ending in "-dev", and a hash listed twice."""
    inventory: dict[bytes, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) != 2 or not SHA256_HEX.fullmatch(fields[0]):
            raise PreflightError(f"dev inventory line {number}: malformed, expected '<sha256-hex> <label>', "
                                 f"got {raw.strip()!r}")
        digest, label = bytes.fromhex(fields[0]), fields[1]
        if not label.endswith("-dev") or label == "-dev":
            raise PreflightError(f"dev inventory line {number}: label {label!r} does not end in '-dev' "
                                 "(docs/05 rules 3 and 5): the inventory lists dev keys only")
        if digest in inventory:
            raise PreflightError(f"dev inventory line {number}: hash {fields[0]} already listed as "
                                 f"{inventory[digest]!r}")
        inventory[digest] = label
    return inventory


def check_dev_keys(srk_table: bytes, digest: bytes, inventory: dict[bytes, str], dev_board: bool) -> list[Finding]:
    """Look the SRK hash to burn, the table's own hash and each key entry's SHA-256 up in the dev-key inventory.
    A match is an error (docs/05 rule 5), or with dev_board a warning naming the label."""
    keys = parse_srk_table(srk_table).keys
    found = [("SRK hash to burn", digest), ("SRK table hash", srk_fuse_hash(srk_table))]
    found += [(f"SRK table key {n}", hashlib.sha256(key).digest()) for n, key in enumerate(keys)]
    findings, seen = [], set()
    for what, value in found:
        if value not in inventory or value in seen:
            continue
        seen.add(value)
        label = inventory[value]
        if dev_board:
            findings.append(Finding("dev key", f"{what}: dev key {label!r}: allowed for a dev board only",
                                    error=False))
        else:
            findings.append(Finding("dev key", f"{what}: dev key {label!r}: expected no dev key in a fuse burn "
                                               "without the dev-board go-ahead (docs/05 rule 5)"))
    return findings


def parse_hab_log(text: str) -> HabLog:
    """Read a captured hab_status console log (format in the module docstring); other "#" lines are notes and
    are skipped. Refused: a digest header given twice or without a 64-digit hex hash, a log with neither
    "No HAB Events Found!" nor an event, and one with both. A missing digest header is left to check_hab_log."""
    digests: dict[str, str] = {}
    events: list[list[str]] = []
    clean = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        header = HAB_LOG_DIGEST.fullmatch(line)
        if header:
            name, value = header[1], header[2]
            if not SHA256_HEX.fullmatch(value):
                raise PreflightError(f"HAB log line {number}: {name} sha256 {value!r} is not 64 hex digits")
            if name in digests:
                raise PreflightError(f"HAB log line {number}: {name} sha256 given twice")
            digests[name] = value.lower()
            continue
        if line.startswith("#"):        # the owner's notes: not console output
            continue
        if HAB_LOG_EVENT.search(line):
            events.append([raw])
        elif events:
            events[-1].append(raw)
        if HAB_LOG_CLEAN in line:
            clean += 1
    if not events and clean != 1:
        raise PreflightError(f"HAB log: expected one '{HAB_LOG_CLEAN}' or a 'HAB Event N' block, got "
                             f"{clean} of the first and none of the second: not one hab_status output")
    if events and clean:
        raise PreflightError(f"HAB log: both '{HAB_LOG_CLEAN}' and {len(events)} HAB Event blocks: "
                             "not one hab_status output")
    return HabLog(digests, not events, tuple("\n".join(block).rstrip() for block in events))


def check_hab_log(log: str, image_sha256s: dict[str, str]) -> list[Finding]:
    """Check a captured hab_status log, as text, against the SHA-256 hex of flash.bin and u-boot.itb: it must
    parse, name both images with these digests, and show no HAB event."""
    try:
        parsed = parse_hab_log(log)
    except PreflightError as e:
        return [Finding("hab log unparseable", str(e))]
    findings = []
    for name in HAB_LOG_IMAGES:
        want, got = image_sha256s.get(name, "").lower(), parsed.digests.get(name)
        if not want:
            findings.append(Finding("hab log digest", f"HAB log: no {name} sha256 given to check the log against"))
        elif got is None:
            findings.append(Finding("hab log digest", f"HAB log: {name} sha256 header missing: expected "
                                                      f"'# {name} sha256: {want}'"))
        elif got != want:
            findings.append(Finding("hab log digest", f"HAB log: {name} sha256 mismatch: the log is for another "
                                                      f"image: expected {want}, got {got}"))
    for n, block in enumerate(parsed.events, 1):
        findings.append(Finding("hab event", f"HAB log: event block {n} of {len(parsed.events)}: expected none, "
                                             f"got:\n{block}"))
    return findings


def check_recovery_evidence(recovery_evidence: str | None, root: Path) -> list[Finding]:
    """The OI2-07 recovery run must be a file under root/evidence/ that evidence/SHA256SUMS lists with its hash."""
    def refuse(why: str) -> list[Finding]:
        return [Finding("recovery evidence", f"fuse burn refused: {why}; expected the confirmed boot-mode and uuu "
                                             "recovery run, committed under evidence/ (OI2-07)")]
    if not recovery_evidence:
        return refuse("no --recovery-evidence given")
    evidence = (root / "evidence").resolve()
    path = (root / recovery_evidence).resolve()
    if not path.is_relative_to(evidence) or path == evidence:
        return refuse(f"{recovery_evidence} is not under evidence/")
    if not path.is_file():
        return refuse(f"{recovery_evidence} is not a file")
    rel = path.relative_to(evidence).as_posix()
    listed, errors = check_evidence.read_manifest(evidence)
    if errors:
        return refuse(f"evidence/{check_evidence.MANIFEST} unreadable: {'; '.join(errors)}")
    if rel not in listed:
        return refuse(f"evidence/{rel} is not listed in evidence/{check_evidence.MANIFEST}")
    got = check_evidence.sha256(path)
    if got != listed[rel]:
        return refuse(f"evidence/{rel} hash mismatch: {check_evidence.MANIFEST} records {listed[rel]}, "
                      f"the file has {got}")
    return []


def check_close(plan: list[FuseWrite], hab_log: str | None, recovery_evidence: str | None,
                image_sha256s: dict[str, str], root: Path = check_evidence.ROOT) -> list[Finding]:
    """Gate the plan's permanent steps. Any fuse write needs the OI2-07 recovery evidence (a path relative to
    root). A write to bank 1 word 3 closes the chip, so it also needs a clean HAB log, as text, for exactly these
    images (OI2-02). An SRK-hash-only plan needs no HAB log: an open chip still boots unsigned images."""
    if not plan:
        return []
    findings = check_recovery_evidence(recovery_evidence, root)
    close = [w for w in plan if (w.bank, w.word) == CLOSE_FUSE]
    if close:
        at = f"line {close[0].line}: close command refused"
        if hab_log is None:
            findings.append(Finding("close gate", f"{at}: no HAB log given; expected a clean hab_status log for "
                                                  "these images before the chip is closed (OI2-02)"))
        else:
            findings += [Finding("close gate", f"{at}: {f.message} (OI2-02)") for f in check_hab_log(hab_log,
                                                                                                    image_sha256s)]
    return findings


# --- command line and fuse-burn record -------------------------------------------

RECORD = "fuse-burn-record"
RECORD_SCHEMA = "fuse-burn-record/1"
OPEN_ITEMS = "https://github.com/samyoon727ca/uas-sec-p2-verified-boot/blob/main/docs/02-cc-boot-chain.md#27-open-items"


def tool_version(root: Path = check_evidence.ROOT) -> str:
    """The repo's git commit, read from .git without running git (this tool starts no process), or "unknown"."""
    try:
        git = root / ".git"
        if git.is_file():                       # a worktree: "gitdir: <path>"
            git = (root / git.read_text().split("gitdir:", 1)[1].strip()).resolve()
        common = (git / (git / "commondir").read_text().strip()).resolve() if (git / "commondir").is_file() else git
        head = (git / "HEAD").read_text().strip()
        if not head.startswith("ref: "):
            commit = head
        else:
            ref = head[5:]
            loose = next((d / ref for d in (git, common) if (d / ref).is_file()), None)
            if loose is not None:
                commit = loose.read_text().strip()
            else:
                packed = (common / "packed-refs").read_text().splitlines() if (common / "packed-refs").is_file() else []
                commit = next((line.split()[0] for line in packed if line.endswith(" " + ref)), "")
    except (OSError, IndexError):
        return "unknown"
    return commit if re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", commit) else "unknown"


def render_record_md(record: dict) -> str:
    """The fuse-burn record as markdown, from the same dict as the JSON."""
    lines = ["# Fuse-burn record", "",
             f"Written by `tools/fuse_preflight.py` at `{record['tool_version']}` on {record['created_utc']}. "
             "Every check passed. The tool read only the files below; it never touched hardware.", "",
             "**Each step below is permanent. Type its commands only with the owner's explicit go-ahead at that "
             "moment (docs/05 rule 5).** U-Boot asks before each write; answer `y` only then. "
             f"See [OI2-02 and OI2-07]({OPEN_ITEMS}).", "",
             "## Inputs", "", "| Input | Path | SHA-256 |", "|---|---|---|"]
    lines += [f"| {name} | `{item['path']}` | `{item['sha256']}` |"
              for name, item in record["inputs"].items() if item is not None]
    lines += ["", "## SRK hash", "", f"`{record['srk_fuse_hash']}`, as fuse words:", "",
              "| Bank | Word | Value |", "|---|---|---|"]
    lines += [f"| {bank} | {word} | `{value}` |" for (bank, word), value in zip(SRK_FUSES, record["fuse_words"])]
    lines += ["", "## Images", "", "| Image | SRK index | IVT offsets |", "|---|---|---|"]
    lines += [f"| {name} | {image['srk_index']} | {', '.join(image['ivt_offsets'])} |"
              for name, image in record["images"].items()]
    lines += ["", "## Warnings", ""] + ([f"- {w}" for w in record["warnings"]] or ["None."])
    for step in record["steps"]:
        lines += ["", f"## Step {step['step']}: {step['title']}", "",
                  "Permanent. Needs the owner's explicit go-ahead at this moment (docs/05 rule 5).", "",
                  "```"] + step["commands"] + ["```"]
    if not any(step["step"] == "B" for step in record["steps"]):
        lines += ["", "No Step B: this plan does not close the chip. Closing it needs its own preflight run, with "
                  "a clean HAB log for these images (OI2-02)."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None, root: Path = check_evidence.ROOT) -> int:
    """Run every check, print every finding, and write DIR/fuse-burn-record.md and .json only if none blocks.

    Exit 0 when the record is written, 1 when the preflight refuses (nothing written), 2 on a usage error.
    --recovery-evidence is a path relative to root, the repo root. The JSON keys (schema "fuse-burn-record/1"):
      schema          "fuse-burn-record/1"
      tool_version    git commit of the repo's HEAD, or "unknown"
      created_utc     ISO 8601 UTC time, "YYYY-MM-DDTHH:MM:SSZ"
      inputs          srk_table, flash_bin, uboot_itb, plan, dev_inventory, hab_log, recovery_evidence: each
                      {"path", "sha256"}, or null when not given
      dev_board       true when --dev-board was given
      srk_fuse_hash   SHA-256 hex of the SRK hash to burn
      fuse_words      the eight words as "0x%08X", bank 6 words 0-3 then bank 7 words 0-3
      images          "flash.bin" and "u-boot.itb": {"srk_index", "ivt_offsets": ["0x..", ...]}
      warnings        every non-blocking finding's message
      steps           [{"step": "A", "title", "commands"}] then, only for a plan that closes the chip,
                      {"step": "B", ...}; commands are exactly what the owner types, in order
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--srk-table", required=True, type=Path, help="CST's SRK_1_2_3_4_table.bin")
    parser.add_argument("--flash-bin", required=True, type=Path, help="signed flash.bin")
    parser.add_argument("--uboot-itb", required=True, type=Path, help="signed u-boot.itb")
    parser.add_argument("--plan", required=True, type=Path, help="planned fuse prog commands")
    parser.add_argument("--dev-inventory", type=Path, help="dev-key hash inventory")
    parser.add_argument("--dev-board", action="store_true", help="the burn is for a dev board: dev keys warn only")
    parser.add_argument("--hab-log", type=Path, help="hab_status capture headed with the image digests")
    parser.add_argument("--recovery-evidence", help="the OI2-07 recovery run, a file under evidence/")
    parser.add_argument("--out", required=True, type=Path, help="folder for the fuse-burn record")
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    data: dict[str, bytes] = {}
    for key in ("srk_table", "flash_bin", "uboot_itb", "plan", "dev_inventory", "hab_log"):
        path = getattr(args, key)
        if path is not None:
            try:
                data[key] = path.read_bytes()
            except OSError as e:
                findings.append(Finding("input", f"--{key.replace('_', '-')} {path}: cannot read: {e.strerror}"))

    def parse(what, *a):
        try:
            return what(*a)
        except PreflightError as e:
            findings.append(Finding("input", str(e)))
        except UnicodeDecodeError as e:
            findings.append(Finding("input", f"a text input is not UTF-8: {e}"))
        return None

    digest = parse(srk_fuse_hash, data["srk_table"]) if "srk_table" in data else None
    plan = parse(lambda b: parse_fuse_plan(b.decode()), data["plan"]) if "plan" in data else None
    inventory = parse(lambda b: parse_dev_inventory(b.decode()), data["dev_inventory"]) \
        if "dev_inventory" in data else None
    hab_log = parse(bytes.decode, data["hab_log"]) if "hab_log" in data else None
    images = {}
    for name, key in (("flash.bin", "flash_bin"), ("u-boot.itb", "uboot_itb")):
        found = parse(extract_srk, getattr(args, key)) if key in data else None
        if found is not None:
            images[name] = found
    sha256s = {key: hashlib.sha256(value).hexdigest() for key, value in data.items()}
    image_sha256s = {name: sha256s[key] for name, key in (("flash.bin", "flash_bin"), ("u-boot.itb", "uboot_itb"))
                     if key in sha256s}

    if digest is not None and plan is not None:
        findings += check_plan(plan, digest)
        findings += check_images(images, digest, plan)
    if digest is not None and inventory is not None:
        findings += check_dev_keys(data["srk_table"], digest, inventory, args.dev_board)
    if args.dev_board:
        findings.append(Finding("dev board", "--dev-board: this burn is for a dev board, so dev keys are allowed; "
                                             "nothing it boots is a release (docs/05 rules 3 and 5)", error=False))
    if plan is not None and (args.hab_log is None or hab_log is not None):
        findings += check_close(plan, hab_log, args.recovery_evidence, image_sha256s, root=root)
    if plan is not None and not plan:
        findings.append(Finding("empty plan", "plan: no fuse prog command"))

    errors = [f for f in findings if f.error]
    for f in findings:
        print(f"{'ERROR' if f.error else 'WARNING'}: {f.kind}: {f.message}")
    if errors:
        print(f"REFUSED: {len(errors)} blocking finding(s); no record written", file=sys.stderr)
        return 1
    md, js = args.out / f"{RECORD}.md", args.out / f"{RECORD}.json"
    if md.exists() or js.exists():
        print(f"REFUSED: {md} or {js} already exists; no record written", file=sys.stderr)
        return 1

    recovery = root / args.recovery_evidence
    sha256s["recovery_evidence"] = check_evidence.sha256(recovery)
    paths = {key: str(getattr(args, key)) for key in sha256s}
    record = {
        "schema": RECORD_SCHEMA,
        "tool_version": tool_version(root),
        "created_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "inputs": {key: {"path": paths[key], "sha256": sha256s[key]} if key in sha256s else None
                   for key in ("srk_table", "flash_bin", "uboot_itb", "plan", "dev_inventory", "hab_log",
                               "recovery_evidence")},
        "dev_board": args.dev_board,
        "srk_fuse_hash": digest.hex(),
        "fuse_words": [hexword(w) for w in fuse_words(digest)],
        "images": {name: {"srk_index": found[0][2], "ivt_offsets": [f"{offset:#x}" for offset, _, _ in found]}
                   for name, found in images.items()},
        "warnings": [f.message for f in findings],
        "steps": [{"step": "A", "title": "burn the SRK hash", "commands": render_srk_commands(fuse_words(digest))}],
    }
    if any((w.bank, w.word) == CLOSE_FUSE for w in plan):
        record["steps"].append({"step": "B", "title": "close the chip",
                                "commands": [f"fuse prog {CLOSE_FUSE[0]} {CLOSE_FUSE[1]} 0x{CLOSE_VALUE:X}"]})
    args.out.mkdir(parents=True, exist_ok=True)
    js.write_text(json.dumps(record, indent=2) + "\n")
    md.write_text(render_record_md(record))
    print(f"wrote {md} and {js}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
