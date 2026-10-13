# References

Every external source P2 relies on, with the version pinned. Facts were checked in the source or document at that version, not in release notes or doc badges. All sources were accessed 2026-10-03, except where a row gives another date.

## P1

| Tag | Source | Version pinned | Used for |
|---|---|---|---|
| [P1] | [samyoon727ca/uas-sec-p1-architecture](https://github.com/samyoon727ca/uas-sec-p1-architecture) | Commit `83c6d2dd39aafe14ff97764c8cbb730b6426fe0b` (baseline 1.0 plus change 1, the `evidence` column); CSVs copied to [`data/p1/`](../data/p1/) | Parent requirements SR-005, SR-010 and SR-018, their threats, VE-07 and VE-08, assumptions A-04, A-08 and A-14, DD-06; the `evidence` column that records a result |

## Companion computer

| Tag | Source | Version pinned | Used for |
|---|---|---|---|
| [UBOOT] | [U-Boot](https://source.denx.de/u-boot/u-boot) release tarball [`u-boot-2026.07.tar.bz2`](https://ftp.denx.de/pub/u-boot/u-boot-2026.07.tar.bz2) | `v2026.07`, tarball SHA-256 `78e8bfc382fe388f9b55aa1daf8c563522a037779b5d4c349d1415e381f1243e`; tag commit `ece349ade2973e220f524ce59e59711cc919263f`. The tarball matches the tag except for dot-files under `lib/lwip/lwip` | See the U-Boot facts table below |
| [UBOOT-SIG] | U-Boot `doc/usage/fit/signature.rst`, `doc/usage/fit/sign-configs.rst` | `v2026.07` | Configuration signing; required keys; hardware signing through an OpenSSL PKCS#11 engine (`mkimage -N`) |
| [UBOOT-MB] | U-Boot `doc/usage/measured_boot.rst` | `v2026.07` | Legacy (`bootm`) measured boot; event log handed over through `linux,sml-base`/`linux,sml-size` |
| [UBOOT-QEMU] | U-Boot `doc/board/emulation/qemu-arm.rst`, `doc/develop/devicetree/dt_qemu.rst` | `v2026.07` | swtpm with QEMU; merging U-Boot nodes into QEMU's devicetree and passing it with `-dtb` |
| [UBOOT-HAB] | U-Boot `doc/imx/habv4/`: `introduction_habv4.txt`, `guides/mx8m_spl_secure_boot.txt`, `guides/mx6_mx7_secure_boot.txt` | `v2026.07`; accessed 2026-10-12 | HABv4: a PKI tree of up to four SRKs; the SRK table hash is burned into fuses; once the chip is closed it "does not load an image that has not been signed using the correct PKI tree"; "an error in SRK Hash results in a part that does not boot". The guides describe no image-version or rollback check |
| [NXP-CST] | NXP *Code-Signing Tool User's Guide*, shipped in NXP's CST package (login required; download URL not recorded) | Rev. 3.3.1 (07/2020); local copy SHA-256 `240c67a9fadcddcf6e642c1ef5891d8a78d1aa4ea4b6766f49a1e7ae16ff12db`; accessed 2026-10-09 | Table 1: HAB4 SRK types are RSA 1024 to 4096 bits and, on the i.MX 8M Plus only, ECC P-256, P-384 and P-521. PKCS#11 back end for HSM signing |
| [NXP-FUSE] | NXP [`uboot-imx` `doc/imx/habv4/guides/mx8m_secure_boot.txt`](https://github.com/nxp-imx/uboot-imx/blob/bb41975aeb4cbd153b49c9fd62da1d64cd65968d/doc/imx/habv4/guides/mx8m_secure_boot.txt) | Branch `lf_v2026.04`, commit `bb41975aeb4cbd153b49c9fd62da1d64cd65968d`; accessed 2026-10-09 | i.MX 8M SRK hash fuses (bank 6 words 0–3, bank 7 words 0–3); closing the chip with `fuse prog 1 3 0x2000000` |
| [DEBIX-GPIO] | Polyhex [DEBIX GPIO manual](https://debix.io/Software/blog_info/id/60.html) (vendor page) | Page dated 2025-10-09; accessed 2026-10-09 | ECSPI1 and ECSPI2 pins on header J2. A secondary source swaps the chip-select and clock pins, so they are checked on the board (OI2-08) |
| [RPI-SB] | Raspberry Pi [`usbboot/docs/secure-boot.md`](https://github.com/raspberrypi/usbboot/blob/12fa1cdbbeab880f7c8e7e797c4ef2831c9f784e/docs/secure-boot.md) | Commit `12fa1cdb` (2026-10-02) | Pi 4 and Pi 5 chain of trust; OTP programming is permanent; `boot.img` signed with RSA-2048 PKCS#1 v1.5; HSM wrapper (`rpi-eeprom-digest -H`); OTP key readable by any kernel code |
| [QEMU] | QEMU [`hw/core/sysbus-fdt.c`](https://gitlab.com/qemu-project/qemu/-/blob/v8.2.2/hw/core/sysbus-fdt.c), [`hw/arm/virt.c`](https://gitlab.com/qemu-project/qemu/-/blob/v8.2.2/hw/arm/virt.c) | `v8.2.2` (Ubuntu `1:8.2.2+ds-0ubuntu1.18`) | `tpm-tis-device` on the `virt` machine; devicetree node `tcg,tpm-tis-mmio` |
| [LINUX] | Linux [`drivers/char/tpm/tpm_tis.c`](https://github.com/torvalds/linux/blob/v6.8/drivers/char/tpm/tpm_tis.c); Ubuntu kernel `6.8.0-146-generic` arm64 `config` | `v6.8`; Ubuntu `6.8.0-146.146` | `tcg,tpm-tis-mmio` match; `CONFIG_TCG_TIS=y` built in |
| [SWTPM] | [swtpm](https://github.com/stefanberger/swtpm) | `0.7.3` (Ubuntu `0.7.3-0ubuntu5.24.04.1`) | Emulated TPM 2.0. At log level 20 it logs every TPM command and response in hex (`SWTPM_IO_Read`, `SWTPM_IO_Write`), which TC-09 searches |
| [TPM2-TOOLS] | [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) `man/` | `5.6` (Ubuntu `5.6-1build4`) | Provisioning on the host: persistent parent, epoch NV index, sealed objects |
| [TPM2-TSS] | [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) ESAPI headers (`include/tss2/tss2_esys.h`) | `4.0.1` (Ubuntu `4.0.1-7.1ubuntu5.1`, arm64 for the guest) | The unseal agent: salted policy sessions, parameter encryption, `Esys_PolicyAuthorize` |

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
| `TPM2_TIS_SPI` needs `DM_SPI` and matches only `tcg,tpm_tis-spi`. It warns that a GPIO-driven TPM reset "should not be used on secure production devices" | `drivers/tpm/Kconfig`, `drivers/tpm/tpm2_tis_spi.c` |
| The i.MX ECSPI driver `MXC_SPI` matches `fsl,imx51-ecspi` and `fsl,imx6ul-ecspi` | `drivers/spi/mxc_spi.c` |
| The i.MX 8M Plus Gateworks Venice GW71xx devicetree has an SPI TPM (`tcg,tpm_tis-spi`) on `ecspi2` | `dts/upstream/src/arm64/freescale/imx8mp-venice-gw71xx.dtsi` |
| DEBIX Model A: board `imx8mp_debix_model_a`, status Maintained; DRAM set up for 2 GB (`PHYS_SDRAM_SIZE`); environment in MMC (`ENV_IS_IN_MMC`); its devicetree enables no ECSPI node | `board/polyhex/imx8mp_debix_model_a/MAINTAINERS`, `include/configs/imx8mp_debix_model_a.h`, `configs/imx8mp_debix_model_a_defconfig`, `dts/upstream/src/arm64/freescale/imx8mp-debix-model-a.dts` |
| With `IMX_HAB`, binman signs SPL and `u-boot.itb` with NXP's CST while building `flash.bin`. Its template defaults to RSA-4096 key files | `arch/arm/dts/imx8mp-u-boot.dtsi`, `tools/binman/etype/nxp_imx8mcst.py` |
| On an open chip (SEC_CONFIG not burned), `imx_hab_authenticate_image` returns success even when authentication fails; failures show only as HAB events. On the i.MX 8M, SEC_CONFIG is fuse bank 1, word 3, bit `0x2000000` | `arch/arm/mach-imx/hab.c`, `arch/arm/mach-imx/imx8m/soc.c` |
| STM32MP1 ROM signatures: ECDSA on `prime256v1` or `brainpool256` only. The STM32MP135F-DK devicetree disables `spi5`, and `stm32mp13_defconfig` does not enable `STM32_SPI` | `arch/arm/mach-stm32mp/ecdsa_romapi.c`, `dts/upstream/src/arm/st/stm32mp135f-dk.dts`, `configs/stm32mp13_defconfig` |
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
| [SP800-57] | [NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) | May 2020 | Table 2: RSA k = 2048 gives 112 bits of security strength; RSA k = 3072 and ECC f = 256–383 give 128; RSA k = 4096 falls between the 128-bit and 192-bit rows, so it gives 128. Table 4: 112-bit strength is disallowed for applying protection from 2031 |

## Tool pins

| Item | Pin | How it is checked |
|---|---|---|
| Ubuntu host tools (QEMU, swtpm, tpm2-tools, cross compilers, dtc; the 32-bit toolchain for TC-11) | Ubuntu 24.04 archive snapshot `20261002T000000Z` ([`cc/emu/host-packages.txt`](../cc/emu/host-packages.txt), [`fc/host-packages.txt`](../fc/host-packages.txt)) | `apt-get update --snapshot`; installed versions compared with the expected versions |
| Guest kernel | `linux-image-6.8.0-146-generic_6.8.0-146.146_arm64.deb` from Launchpad | SHA-256 `ee35dffd32c672d6b1814c0d9c8001c1656e06e718ebd5fb15565d0b7e51e418`, matching the signed `noble-updates` index |
| Guest busybox | `busybox-static_1.36.1-6ubuntu3.1_arm64.deb` from Launchpad | SHA-256 `d96535e0402c011e0ee43449799df2f4504d44b842e4f2b3a6cbc845508eaafc`, matching the signed index |
| Guest TPM libraries for the unseal agent: glibc, libcrypto, tpm2-tss ESAPI, MU, SYS, RC, device TCTI and headers | Eight arm64 packages from Launchpad, listed with their SHA-256 in [`cc/emu/guest.lock`](../cc/emu/guest.lock) | Each SHA-256 matches the signed `noble-updates` index for arm64 (`ports.ubuntu.com`, checked 2026-10-13); `cc/build.sh` refuses any file that differs |
| PX4 source | Tag `v1.18.0-rc1`, commit `fca3df865af36124a28c9d607e850f111dbaaea9` ([`fc/px4/pin.txt`](../fc/px4/pin.txt)) | `fc/clone-px4.sh` refuses any other commit; `fc/build.sh` records the commit it built |
| PX4 build container | `ghcr.io/px4/px4-dev:v1.17.0-rc2`, the default in PX4's `Tools/ci/build_all_config.yml` at that tag, by manifest-list digest `sha256:5e7ad18c75c3a5a655d5adfde4ab1eb216dd4bee7710941b6cd122f3969a7fed` (amd64 `sha256:e4c36e7e…fff0`) | Pulled by digest |
| GitHub Actions | Full commit SHAs, as in P1 | Workflow review |
