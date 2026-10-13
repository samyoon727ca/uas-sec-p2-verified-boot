"""Unit tests for tools/predict_pcrs.py."""
from __future__ import annotations

import base64
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "ve07"))
import boot_cases as bc  # noqa: E402
import predict_pcrs as pp  # noqa: E402
from test_boot_cases import make_fdt  # noqa: E402

DTB = make_fdt({"model": b"test\0"})
VERSION = b"U-Boot 2026.07 (Jul 06 2026 - 23:50:43 +0000)\0"
BOOTARGS = b"console=ttyAMA0 rdinit=/init panic=-1"
UBOOT = b"\x00junk\0U-Boot SPL 2026.07 (Jul 06 2026 - 23:50:43 +0000)\0" + VERSION + \
    b"more\0bootcmd=virtio scan\0bootargs=" + BOOTARGS + b"\0\0"


def fit(**over) -> bytes:
    tree = {"images": {"kernel": {"data": b"KERNEL"}, "ramdisk": {"data": b"INITRD"},
                       "fdt": {"data": DTB + b"\0\0\0\0", "compression": b"none\0"},
                       "kernel-2": {"data": b"OTHER"}},
            "configurations": {"default": b"conf\0",
                               "conf": {"kernel": b"kernel\0", "ramdisk": b"ramdisk\0", "fdt": b"fdt\0"},
                               "conf-2": {"kernel": b"kernel-2\0", "ramdisk": b"ramdisk\0", "fdt": b"fdt\0"}}}
    for path, value in over.items():
        node = tree
        *parents, last = path.split("/")
        for p in parents:
            node = node[p]
        if value is None:
            del node[last]
        else:
            node[last] = value
    return make_fdt(tree)


def event_log(events: list[pp.Event], banks=(0x0004, 0x000B)) -> bytes:
    """Serialize events as a crypto-agile TCG2 log; the non-SHA-256 banks get filler digests."""
    sizes = {0x0004: 20, 0x000B: 32, 0x000C: 48}
    spec = pp.SPEC_ID_SIGNATURE + struct.pack("<IBBBBI", 0, 0, 2, 2, 2, len(banks))
    spec += b"".join(struct.pack("<HH", b, sizes[b]) for b in banks) + b"\0"
    out = struct.pack("<II", 0, pp.EV_NO_ACTION) + bytes(20) + struct.pack("<I", len(spec)) + spec
    for ev in events:
        out += struct.pack("<III", ev.pcr, ev.type, len(banks))
        for b in banks:
            digest = bytes.fromhex(ev.digest) if b == 0x000B else b"\xaa" * sizes[b]
            out += struct.pack("<H", b) + digest
        out += struct.pack("<I", len(ev.data)) + ev.data
    return out


def extend(*digests: bytes) -> str:
    pcr = bytes(32)
    for d in digests:
        pcr = hashlib.sha256(pcr + d).digest()
    return pcr.hex()


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class FdtTest(unittest.TestCase):
    def test_parses_nodes_and_properties(self):
        tree = pp.parse_fdt(fit())
        self.assertEqual(tree.get("/images/kernel").props["data"], b"KERNEL")
        self.assertEqual(tree.get("/configurations").string("default"), "conf")
        with self.assertRaises(KeyError):
            tree.get("/images/missing")

    def test_rejects_non_fdt(self):
        with self.assertRaises(ValueError):
            pp.parse_fdt(b"\0" * 64)


class FitImagesTest(unittest.TestCase):
    def test_default_configuration(self):
        images = pp.fit_images(fit())
        self.assertEqual((images.config, images.kernel, images.ramdisk), ("conf", b"KERNEL", b"INITRD"))

    def test_devicetree_is_measured_as_its_totalsize(self):
        self.assertEqual(pp.fit_images(fit()).fdt, DTB)

    def test_named_configuration(self):
        self.assertEqual(pp.fit_images(fit(), "conf-2").kernel, b"OTHER")

    def test_refuses_what_it_cannot_predict(self):
        cases = {
            "external data": {"images/kernel": {"data-offset": b"\0\0\0\0", "data-size": b"\0\0\0\x06"}},
            "two devicetrees": {"configurations/conf/fdt": b"fdt\0fdt\0"},
            "compressed devicetree": {"images/fdt/compression": b"gzip\0"},
        }
        for name, over in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                pp.fit_images(fit(**over))


class UbootTest(unittest.TestCase):
    def test_version_string_skips_the_spl(self):
        self.assertEqual(pp.uboot_version(UBOOT), VERSION)

    def test_version_string_must_be_unique(self):
        other = b"\0U-Boot 2026.10 (Oct 06 2026 - 10:00:00 +0000)\0"
        for blob in (b"nothing here", UBOOT + other):
            with self.subTest(blob[:12]), self.assertRaises(ValueError):
                pp.uboot_version(blob)

    def test_bootargs_from_the_default_environment(self):
        self.assertEqual(pp.uboot_bootargs(UBOOT), BOOTARGS + b"\0")
        with self.assertRaises(ValueError):
            pp.uboot_bootargs(VERSION)


class PredictTest(unittest.TestCase):
    def setUp(self):
        self.pred = pp.predict(fit(), UBOOT)

    def test_events_in_bootm_order(self):
        got = [(e.pcr, e.type, e.data) for e in self.pred.events]
        sep = struct.pack("<I", 0xFFFFFFFF)
        self.assertEqual(got[:5], [(0, pp.EV_S_CRTM_VERSION, VERSION), (8, pp.EV_COMPACT_HASH, b"linux\0"),
                                   (9, pp.EV_COMPACT_HASH, b"initrd\0"), (1, pp.EV_TABLE_OF_DEVICES, b"dts\0"),
                                   (1, pp.EV_PLATFORM_CONFIG_FLAGS, BOOTARGS + b"\0")])
        self.assertEqual(got[5:], [(i, pp.EV_SEPARATOR, sep) for i in range(8)])

    def test_policy_pcrs(self):
        sep = h(b"\xff" * 4)
        self.assertEqual(self.pred.pcrs[0], extend(h(VERSION), sep))
        self.assertEqual(self.pred.pcrs[1], extend(h(DTB), h(BOOTARGS + b"\0"), sep))
        self.assertEqual(self.pred.pcrs[8], extend(h(b"KERNEL")))
        self.assertEqual(self.pred.pcrs[9], extend(h(b"INITRD")))
        self.assertEqual(self.pred.pcrs[5], extend(sep))

    def test_explicit_bootargs(self):
        pred = pp.predict(fit(), UBOOT, bootargs="")
        self.assertEqual(pred.bootargs, b"\0")
        self.assertNotEqual(pred.pcrs[1], self.pred.pcrs[1])
        self.assertEqual(pred.pcrs[8], self.pred.pcrs[8])

    def test_each_item_moves_only_its_pcr(self):
        changed = {
            "kernel": (pp.predict(fit(**{"images/kernel/data": b"KERNEL!"}), UBOOT), {8}),
            "initramfs": (pp.predict(fit(**{"images/ramdisk/data": b"INITRD!"}), UBOOT), {9}),
            "devicetree": (pp.predict(fit(**{"images/fdt/data": make_fdt({"model": b"x\0"})}), UBOOT), {1}),
            "bootargs": (pp.predict(fit(), UBOOT, bootargs="quiet"), {1}),
            "U-Boot": (pp.predict(fit(), UBOOT.replace(b"23:50:43", b"23:50:44", 2)), {0}),
        }
        for name, (pred, pcrs) in changed.items():
            with self.subTest(name):
                moved = {i for i in pp.POLICY_PCRS if pred.pcrs[i] != self.pred.pcrs[i]}
                self.assertEqual(moved, pcrs)


class EventLogTest(unittest.TestCase):
    def setUp(self):
        self.pred = pp.predict(fit(), UBOOT)

    def test_round_trip_with_several_banks(self):
        log = pp.parse_event_log(event_log(self.pred.events, banks=(0x0004, 0x000B, 0x000C)))
        self.assertEqual([e.describe() for e in log], [e.describe() for e in self.pred.events])
        self.assertEqual(pp.replay(log), self.pred.pcrs)

    def test_trailing_zeros_end_the_log(self):
        log = pp.parse_event_log(event_log(self.pred.events) + bytes(256))
        self.assertEqual(len(log), len(self.pred.events))

    def test_rejects_a_log_without_a_spec_id_event(self):
        with self.assertRaises(ValueError):
            pp.parse_event_log(event_log(self.pred.events).replace(pp.SPEC_ID_SIGNATURE, b"Spec ID Event00\0"))

    def test_rejects_a_truncated_log(self):
        with self.assertRaises((ValueError, struct.error)):
            pp.parse_event_log(event_log(self.pred.events)[:-3])


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.pred = pp.predict(fit(), UBOOT)
        self.log = pp.parse_event_log(event_log(self.pred.events))
        self.measured = {i: self.pred.pcrs[i] for i in pp.POLICY_PCRS}

    def test_all_equal(self):
        checks = pp.compare(self.pred, self.log, self.measured)
        self.assertEqual(len(checks), 1 + 2 * len(pp.POLICY_PCRS))
        self.assertTrue(all(c["ok"] for c in checks))

    def test_changed_event_is_reported_with_its_index(self):
        events = list(self.pred.events)
        events[2] = pp.Event(9, pp.EV_COMPACT_HASH, "00" * 32, b"initrd\0")
        checks = pp.compare(self.pred, pp.parse_event_log(event_log(events)))
        failed = [c for c in checks if not c["ok"]]
        self.assertEqual([c["kind"] for c in failed], ["eventlog", "replayed"])
        self.assertEqual(failed[0]["observed"]["index"], 2)
        self.assertTrue(failed[1]["pattern"].startswith("PCR 9"))

    def test_missing_or_extra_events_fail(self):
        for log in (self.log[:-1], self.log + self.log[-1:]):
            with self.subTest(len(log)):
                self.assertFalse(pp.compare(self.pred, log)[0]["ok"])

    def test_measured_mismatch(self):
        measured = {**self.measured, 1: "11" * 32}
        failed = [c for c in pp.compare(self.pred, measured=measured) if not c["ok"]]
        self.assertEqual([c["pattern"][:5] for c in failed], ["PCR 1"])
        failed = [c for c in pp.compare(self.pred, measured={}) if not c["ok"]]
        self.assertEqual(len(failed), len(pp.POLICY_PCRS))

    def test_parse_measured(self):
        text = "noise\r\nP2-PCR sha256 0 " + "AB" * 32 + "\r\n8 " + "cd" * 32 + "\nP2-PCR sha256 9 short\n"
        self.assertEqual(pp.parse_measured(text), {0: "ab" * 32, 8: "cd" * 32})


class HarnessPcrChecksTest(unittest.TestCase):
    """tests/ve07/boot_cases.py reads what cc/initramfs/init prints."""

    def setUp(self):
        self.pred = pp.predict(fit(), UBOOT)

    def console(self, events, pcrs, log=True):
        lines = ["[    1.0] kernel noise", "P2-INITRAMFS-OK kernel=6.8.0-146-generic"]
        lines += [f"P2-PCR sha256 {i} {pcrs.get(i, '00' * 32).upper()}" for i in range(10)]
        if log:
            b64 = base64.b64encode(event_log(events)).decode()
            lines += ["P2-EVENTLOG-BEGIN", *[b64[i:i + 76] for i in range(0, len(b64), 76)], "P2-EVENTLOG-END"]
        return "\x1b[0m" + "\r\n".join(lines) + "\r\n"

    def test_pass(self):
        checks = bc.pcr_checks(self.pred, self.console(self.pred.events, self.pred.pcrs))
        self.assertTrue(all(c["ok"] for c in checks), [c for c in checks if not c["ok"]])

    def test_a_boot_loader_that_measures_nothing_fails(self):
        checks = bc.pcr_checks(self.pred, self.console([], {}))
        self.assertFalse(checks[0]["ok"])
        self.assertFalse(all(c["ok"] for c in checks))

    def test_missing_event_log_fails(self):
        checks = bc.pcr_checks(self.pred, self.console(self.pred.events, self.pred.pcrs, log=False))
        self.assertEqual([c["kind"] for c in checks if not c["ok"]], ["eventlog"])

    def test_corrupt_event_log_fails(self):
        text = self.console(self.pred.events, self.pred.pcrs).replace("P2-EVENTLOG-BEGIN\r\n",
                                                                      "P2-EVENTLOG-BEGIN\r\n!!\r\n")
        self.assertFalse(all(c["ok"] for c in bc.pcr_checks(self.pred, text)))

    def test_ten_pcr_lines_expected(self):
        text = bc.clean(self.console(self.pred.events, self.pred.pcrs))
        self.assertEqual(len(__import__("re").findall(bc.PCR_LINE, text)), 10)


if __name__ == "__main__":
    unittest.main()
