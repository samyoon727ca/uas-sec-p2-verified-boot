# References

Every external source P2 relies on, with the version pinned. Facts were checked in the source or document at that version, not in release notes or doc badges. All sources were accessed 2026-10-03.

## P1

| Tag | Source | Version pinned | Used for |
|---|---|---|---|
| [P1] | [samyoon727ca/uas-sec-p1-architecture](https://github.com/samyoon727ca/uas-sec-p1-architecture) | Commit `7aadc83f363fc4d1c24f987d50a831d07ba86f18` (baseline 1.0); CSVs copied to [`data/p1/`](../data/p1/) | Parent requirements SR-005, SR-010 and SR-018, their threats, VE-07 and VE-08, assumptions A-04, A-08 and A-14, DD-06 |

## Companion computer

| Tag | Source | Version pinned | Used for |
|---|---|---|---|
| [UBOOT] | [U-Boot](https://source.denx.de/u-boot/u-boot) release tarball [`u-boot-2026.07.tar.bz2`](https://ftp.denx.de/pub/u-boot/u-boot-2026.07.tar.bz2) | `v2026.07`, tarball SHA-256 `78e8bfc382fe388f9b55aa1daf8c563522a037779b5d4c349d1415e381f1243e`; tag commit `ece349ade2973e220f524ce59e59711cc919263f`. The tarball matches the tag except for dot-files under `lib/lwip/lwip` | See the U-Boot facts table below |
| [UBOOT-SIG] | U-Boot `doc/usage/fit/signature.rst`, `doc/usage/fit/sign-configs.rst` | `v2026.07` | Configuration signing; required keys; hardware signing through an OpenSSL PKCS#11 engine (`mkimage -N`) |
| [UBOOT-MB] | U-Boot `doc/usage/measured_boot.rst` | `v2026.07` | Legacy (`bootm`) measured boot; event log handed over through `linux,sml-base`/`linux,sml-size` |
| [UBOOT-QEMU] | U-Boot `doc/board/emulation/qemu-arm.rst`, `doc/develop/devicetree/dt_qemu.rst` | `v2026.07` | swtpm with QEMU; merging U-Boot nodes into QEMU's devicetree and passing it with `-dtb` |
| [RPI-SB] | Raspberry Pi [`usbboot/docs/secure-boot.md`](https://github.com/raspberrypi/usbboot/blob/12fa1cdbbeab880f7c8e7e797c4ef2831c9f784e/docs/secure-boot.md) | Commit `12fa1cdb` (2026-10-02) | Pi 4 and Pi 5 chain of trust; OTP programming is permanent; `boot.img` signed with RSA-2048 PKCS#1 v1.5; HSM wrapper (`rpi-eeprom-digest -H`); OTP key readable by any kernel code |
| [QEMU] | QEMU [`hw/core/sysbus-fdt.c`](https://gitlab.com/qemu-project/qemu/-/blob/v8.2.2/hw/core/sysbus-fdt.c), [`hw/arm/virt.c`](https://gitlab.com/qemu-project/qemu/-/blob/v8.2.2/hw/arm/virt.c) | `v8.2.2` (Ubuntu `1:8.2.2+ds-0ubuntu1.18`) | `tpm-tis-device` on the `virt` machine; devicetree node `tcg,tpm-tis-mmio` |
| [LINUX] | Linux [`drivers/char/tpm/tpm_tis.c`](https://github.com/torvalds/linux/blob/v6.8/drivers/char/tpm/tpm_tis.c); Ubuntu kernel `6.8.0-146-generic` arm64 `config` | `v6.8`; Ubuntu `6.8.0-146.146` | `tcg,tpm-tis-mmio` match; `CONFIG_TCG_TIS=y` built in |
| [SWTPM] | [swtpm](https://github.com/stefanberger/swtpm) | `0.7.3` (Ubuntu `0.7.3-0ubuntu5.24.04.1`) | Emulated TPM 2.0 |
| [TPM2-TOOLS] | [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) `man/` | `5.6` (Ubuntu `5.6-1build4`) | Policy, NV and unseal commands |

**U-Boot facts relied on**, all checked at `v2026.07`:

| Fact | Where |
|---|---|
| No FIT anti-rollback option. The only rollback indexes are in Android Verified Boot | `boot/Kconfig`, `lib/libavb/` |
| `LEGACY_IMAGE_FORMAT` defaults off when `FIT_SIGNATURE` is set, but `qemu_arm64_defconfig` turns it on | `boot/Kconfig`, `configs/qemu_arm64_defconfig` |
| `BOOTDELAY=-2` autoboots with no delay and no check for abort | `boot/Kconfig` |
| `bootm` measures the kernel into PCR 8, the initrd into PCR 9, and the devicetree (`MEASURE_DEVICETREE`) and `bootargs` into PCR 1, after finding the images and before loading them or applying devicetree fixups | `boot/bootm.c` (`bootm_measure`, `bootm_run_states`) |
| `bootm` ignores the return value of `bootm_measure`, so a failed measurement does not stop the boot | `boot/bootm.c` |
| Measurement starts by extending PCR 0 with the U-Boot version string (`EV_S_CRTM_VERSION`) | `lib/tpm_tcg2.c` |
| SPI TPMs use `TPM2_TIS_SPI`; QEMU's MMIO TPM uses `TPM2_MMIO` | `drivers/tpm/Kconfig` |
| No SPI or I2C controller driver for BCM2835/BCM2711, and no RP1 driver. The only route to an SPI TPM on a Raspberry Pi is GPIO soft SPI (`SOFT_SPI`, `spi-gpio`) | `drivers/spi/`, `drivers/i2c/`, `drivers/gpio/bcm2835_gpio.c` |
| The `tpm2` shell command has no NV read or write; the C API has `tpm2_nv_read_value` | `cmd/tpm-v2.c`, `include/tpm-v2.h` |
| On QEMU the board takes its devicetree from the prior stage; `OF_SEPARATE` is refused at build time | `dts/Kconfig`, build check `OFCHK` |

## Flight controller

| Tag | Source | Version pinned | Used for |
|---|---|---|---|
| [PX4-SECBOOT] | [PX4 Guide: Bootloader Secure Boot](https://github.com/PX4/PX4-Autopilot/blob/v1.18.0-rc1/docs/en/advanced_config/bootloader_secure_boot.md) | Tag `v1.18.0-rc1`, commit `fca3df865af36124a28c9d607e850f111dbaaea9` | Ed25519 via monocypher; signed image layout and TOC; `px4_fmu-v6x` example; key generation; SWD needed to install the boot loader and to recover from a lost key |
| [PX4-BL] | PX4-Autopilot source: [`platforms/nuttx/src/bootloader/common/`](https://github.com/PX4/PX4-Autopilot/tree/v1.18.0-rc1/platforms/nuttx/src/bootloader/common) (`bl.c`, `crypto.c`, `image_toc.c`), [`src/include/image_toc.h`](https://github.com/PX4/PX4-Autopilot/blob/v1.18.0-rc1/src/include/image_toc.h), [`Tools/secure_bootloader/`](https://github.com/PX4/PX4-Autopilot/tree/v1.18.0-rc1/Tools/secure_bootloader), [`boards/px4/fmu-v6x/`](https://github.com/PX4/PX4-Autopilot/tree/v1.18.0-rc1/boards/px4/fmu-v6x), [`src/drivers/stub_keystore/Kconfig`](https://github.com/PX4/PX4-Autopilot/blob/v1.18.0-rc1/src/drivers/stub_keystore/Kconfig); monocypher submodule | `v1.18.0-rc1`; monocypher `baca5d31259c598540e4d1284bc8d8f793abf83a` | Only `px4_fmu-v6x` has secure-boot variants; signature check only, no version or rollback check (`image_cert_t` is defined but unused by the boot loader); no flash write-protection set by the boot loader; `VERIFY_SIG` uploader opcode; four public-key slots `PUBLIC_KEY0`–`PUBLIC_KEY3`; `sign_firmware.py` reads the raw private key from JSON |
| [PX4-6X] | [PX4 Guide: Holybro Pixhawk 6X](https://github.com/PX4/PX4-Autopilot/blob/v1.18.0-rc1/docs/en/flight_controller/pixhawk6x.md) | `v1.18.0-rc1` | STM32H753; build target `px4_fmu-v6x_default`; SWD and console on the FMU Debug port (Pixhawk Debug Full, JST SM10B) |
| [PX4-BLUPD] | [PX4 Guide: Bootloader Update](https://github.com/PX4/PX4-Autopilot/blob/v1.18.0-rc1/docs/en/advanced_config/bootloader_update.md) | `v1.18.0-rc1` | Debug-probe and `SYS_BL_UPDATE` boot-loader update paths |

PX4 `v1.18.0` has not been released: the newest v1.18 tag on 2026-10-03 is `v1.18.0-rc1`. P2 follows P1's DD-06 and re-pins at release.

## Standards

| Tag | Source | Version pinned | Used for |
|---|---|---|---|
| [TCG-P1] | [TCG TPM 2.0 Library, Part 1: Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf) | Level 00 Revision 01.59 | §37.2.6.3: a counter's first increment exceeds any value it has held, so its starting value differs per TPM. §37.2.6.4: a bit field starts at zero and is only ever OR'd. Figure 16: `TPM2_PolicyAuthorize` to avoid PCR brittleness |
| [TCG-P2] | [TCG TPM 2.0 Library, Part 2: Structures](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf) | Revision 01.59 | Table 18: `TPM_EO_BITCLEAR` is "all bits SET in B are CLEAR in A ((A&B)=0)". The tpm2-tools 5.6 man page words `bc` the other way round; the spec governs |
| [SP800-57] | [NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) | May 2020 | Table 2: RSA k = 2048 gives 112 bits of security strength; RSA k = 3072 and ECC f = 256–383 give 128 |

## Tool pins

| Item | Pin | How it is checked |
|---|---|---|
| Ubuntu host tools (QEMU, swtpm, tpm2-tools, cross compiler, dtc) | Ubuntu 24.04 archive snapshot `20261002T000000Z` | `apt-get update --snapshot`; installed versions compared with the expected versions |
| Guest kernel | `linux-image-6.8.0-146-generic_6.8.0-146.146_arm64.deb` from Launchpad | SHA-256 `ee35dffd32c672d6b1814c0d9c8001c1656e06e718ebd5fb15565d0b7e51e418`, matching the signed `noble-updates` index |
| Guest busybox | `busybox-static_1.36.1-6ubuntu3.1_arm64.deb` from Launchpad | SHA-256 `d96535e0402c011e0ee43449799df2f4504d44b842e4f2b3a6cbc845508eaafc`, matching the signed index |
| GitHub Actions | Full commit SHAs, as in P1 | Workflow review |
