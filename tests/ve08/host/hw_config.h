/*
 * Host stand-in for boards/px4/fmu-v6x/src/hw_config.h at PX4 v1.18.0-rc1: only
 * the values PX4's image_toc.c and boot-loader crypto.c read, unchanged from
 * that file, so that PX4's own find_toc() and verify_app() can run on the host
 * (tests/ve08, TC-11).
 */
#pragma once

#define APP_LOAD_ADDRESS               0x08020000
#define BOOTLOADER_USE_SECURITY        1
#define BOOTLOADER_SIGNING_ALGORITHM   CRYPTO_ED25519
#define BOARD_IMAGE_TOC_OFFSET         0x800

/* The board reads _FLASH_KBYTES from the device at run time; the STM32H753 has 2 MiB. */
#define BOARD_FLASH_SIZE               (2048 * 1024)
