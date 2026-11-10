# Bench log

One entry per bench session, newest first: what was done, what went wrong and what changed in the [manual](README.md). Raw photos and console logs stay in the owner's session folder; the ones the repo needs are copied into `img/` (resized, metadata stripped) or `evidence/`.

## 2026-11-09 (desk review, no bench work)

Read the 2026-10-24 session folder: two board photos (top and underside), two Device Manager screenshots and one of the DEBIX images page. It holds no PuTTY log and no wiring photo, so Step 1.4 onward (wiring, boot, login) is not recorded as run.

- **Image (1.1).** The downloaded `DEBIX-Model-A-B-Infinity_Ubuntu22.04_L6.1.22_V3.14_20260325.img` is 4,294,967,296 bytes, and its MD5, computed on the PC, is `16C56AA936BC02503C8AB4CC4DF4B048`, equal to the one DEBIX lists. Whether card A has been written is not recorded.
- **Console port (1.2).** The Debug Probe appears in Device Manager as `USB Serial Device (COM3)`, working properly.
- **Board facts confirmed from the photos (1.3).**
  - J2 is the pair of pin columns at the board edge. The silk prints `40` and `39` at its far end, with 39 in the column at the edge, so the odd pins run along the edge. On the underside the pad at the Ethernet end of that column is square: pin 1.
  - SW1 is not fitted. Its four pads are bare, and the legend beside them reads `01` USB, `10` eMMC, `11` TF. The schematic's table agrees: `BOOT_MODE1`, `BOOT_MODE0` = 00 internal fuses, 01 USB serial download, 10 eMMC, 11 SD.
  - PWR is the upper USB-C port and OTG the lower, as the silk below each one reads.
- **New: J10 and J6 sit right beside J2.** The top photo shows a second pair of pin columns next to J2, at the same pitch. The schematic names them J10 (dual LVDS output, 30 pins) and J6 (second Ethernet, 12 pins), both surface-mount. The manual's diagram showed only J2, so a reader counting "two rows" could have landed on them. The manual now says how to tell them apart, the board diagram draws them, and an annotated crop of the photo is in `img/j2-photo.jpg` (cropped to the header, re-encoded without metadata).
- **Still open.** With SW1 unfitted, the photos don't show which boot mode the board is strapped to. The first boot from card A answers that (OI2-07, Step 2).

## 2026-10-24

- Started the manual with Step 1. Steps 1 to 3 need no TPM. The ANAVI TPM 2.0 is on pre-order from Crowd Supply, shipping about 2026-11-13.
- **Correction before any wiring.** Adafruit's page for the #1919 jumpers says each 2.0 mm end is "a single 2x2.00mm socket", so every housing holds two wires. The earlier plan fitted one wire per housing across J2's two rows. That would have left a live second wire on pin 8 (5 V), pin 10 (power key) or pin 12 (board reset). The manual now uses five housings, A to E, each placed where both pins are wanted or the spare pin is GND.
- DEBIX's current Ubuntu 22.04 image is V3.14 (`DEBIX-Model-A-B-Infinity_Ubuntu22.04_L6.1.22_V3.14_20260325.img`, Linux 6.1.22). The earlier plan named V3.5.
