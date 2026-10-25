# Bench log

One entry per bench session, newest first: what was done, what went wrong and what changed in the [manual](README.md). Raw photos and console logs stay in the owner's session folder; the ones the repo needs are copied into `img/` (resized, metadata stripped) or `evidence/`.

## 2026-10-24

- Started the manual with Step 1. Steps 1 to 3 need no TPM. The ANAVI TPM 2.0 is on pre-order from Crowd Supply, shipping about 2026-11-13.
- **Correction before any wiring.** Adafruit's page for the #1919 jumpers says each 2.0 mm end is "a single 2x2.00mm socket", so every housing holds two wires. The earlier plan fitted one wire per housing across J2's two rows. That would have left a live second wire on pin 8 (5 V), pin 10 (power key) or pin 12 (board reset). The manual now uses five housings, A to E, each placed where both pins are wanted or the spare pin is GND.
- DEBIX's current Ubuntu 22.04 image is V3.14 (`DEBIX-Model-A-B-Infinity_Ubuntu22.04_L6.1.22_V3.14_20260325.img`, Linux 6.1.22). The earlier plan named V3.5.
