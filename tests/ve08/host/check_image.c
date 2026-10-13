/*
 * check_image: would the px4_fmu-v6x secure boot loader start this image? (TC-11)
 *
 *     check_image <image.bin>
 *
 * Built for a 32-bit host (gcc -m32) with PX4's own code at v1.18.0-rc1:
 * find_toc() from platforms/nuttx/src/bootloader/common/image_toc.c,
 * verify_app() from .../common/crypto.c, the stub keystore with the public key
 * given as PUBLIC_KEY0, and monocypher. A 32-bit build keeps the TOC's pointer
 * fields at the 4 bytes they have on the STM32H753, so the TOC needs no
 * translation.
 *
 * The image is mapped at its real flash address (APP_LOAD_ADDRESS), in a flash
 * area that is otherwise erased (0xFF). main() then walks the TOC as the boot
 * loader's jump_to_app() does in bl.c: entry 0 must verify, or the boot loader
 * stays put; later entries with TOC_FLAG1_CHECK_SIGNATURE are skipped if they do
 * not verify; the BOOT entry sets the application base. COPY entries are not
 * copied on the host.
 *
 * Prints one "P2-FC" line per finding and exits 0 if the boot loader would start
 * the image, 1 if it would stay in the boot loader, 2 on a usage or I/O error.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hw_config.h"
#include "image_toc.h"
#include "crypto.h"
#include <px4_platform_common/crypto_backend.h>

#define FLASH_START (APP_LOAD_ADDRESS & ~(BOARD_FLASH_SIZE - 1))
#define FLASH_END   (FLASH_START + BOARD_FLASH_SIZE)

_Static_assert(sizeof(void *) == 4, "build with -m32: the TOC holds 32-bit addresses");
_Static_assert(sizeof(image_toc_entry_t) == 24, "TOC entry layout differs from the STM32H753's");

static int stays(const char *why)
{
	printf("P2-FC result: stays in the boot loader: %s\n", why);
	return 1;
}

int main(int argc, char **argv)
{
	const image_toc_entry_t *toc;
	uintptr_t app_base = 0;
	uint8_t len, i;
	uint8_t *flash;
	FILE *f;
	long size;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <image.bin>\n", argv[0]);
		return 2;
	}
	flash = mmap((void *)FLASH_START, BOARD_FLASH_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (flash != (uint8_t *)FLASH_START) {
		perror("mmap of the flash area");
		return 2;
	}
	memset(flash, 0xff, BOARD_FLASH_SIZE);

	f = fopen(argv[1], "rb");
	if (!f || fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
		perror(argv[1]);
		return 2;
	}
	if ((uintptr_t)size > FLASH_END - APP_LOAD_ADDRESS ||
	    fread((void *)APP_LOAD_ADDRESS, 1, (size_t)size, f) != (size_t)size) {
		fprintf(stderr, "%s: cannot place %ld bytes at 0x%08x\n", argv[1], size, APP_LOAD_ADDRESS);
		return 2;
	}
	fclose(f);
	mprotect(flash, BOARD_FLASH_SIZE, PROT_READ);
	printf("P2-FC image: %ld bytes at 0x%08x\n", size, APP_LOAD_ADDRESS);

	crypto_init();
	if (!find_toc(&toc, &len))
		return stays("no valid TOC");
	for (i = 0; i < len; i++)
		printf("P2-FC toc %u: %.4s 0x%08" PRIxPTR "-0x%08" PRIxPTR " signature=%u key=%u flags=0x%02x\n", i,
		       (const char *)toc[i].name, (uintptr_t)toc[i].start, (uintptr_t)toc[i].end, toc[i].signature_idx,
		       toc[i].signature_key, toc[i].flags1);

	if (!verify_app(0, toc))
		return stays("TOC entry 0 does not verify");
	printf("P2-FC verified: entry 0 (%.4s) with key slot %u\n", (const char *)toc[0].name, toc[0].signature_key);

	for (i = 0; i < len; i++) {
		if (i != 0 && toc[i].flags1 & TOC_FLAG1_CHECK_SIGNATURE && !verify_app(i, toc)) {
			printf("P2-FC skipped: entry %u (%.4s) does not verify\n", i, (const char *)toc[i].name);
			continue;
		}
		if (toc[i].flags1 & TOC_FLAG1_DECRYPT && !decrypt_app(i, toc)) {
			printf("P2-FC skipped: entry %u (%.4s) does not decrypt\n", i, (const char *)toc[i].name);
			continue;
		}
		if (toc[i].flags1 & TOC_FLAG1_BOOT)
			app_base = (uintptr_t)toc[i].start;
	}
	if (app_base == 0)
		return stays("no bootable entry");
	printf("P2-FC result: starts the application at 0x%08" PRIxPTR "\n", app_base);
	return 0;
}
