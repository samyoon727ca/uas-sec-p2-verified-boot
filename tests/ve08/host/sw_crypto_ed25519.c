/*
 * The Ed25519 path of PX4's src/drivers/sw_crypto/crypto.c (v1.18.0-rc1), for
 * the host. That file also builds libtomcrypt algorithms the boot loader never
 * calls; this keeps only what verify_app() reaches. crypto_signature_check()
 * gets the key for key_index from the stub keystore and returns
 * crypto_ed25519_check(signature, key, message, size) == 0, as PX4's does.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <px4_platform_common/crypto_backend.h>
#include <lib/crypto/monocypher/src/optional/monocypher-ed25519.h>

static int crypto_open_count;

void crypto_init(void)
{
	keystore_init();
}

crypto_session_handle_t crypto_open(px4_crypto_algorithm_t algorithm)
{
	crypto_session_handle_t ret = { 0 };

	ret.keystore_handle = keystore_open();
	if (keystore_session_handle_valid(ret.keystore_handle)) {
		ret.algorithm = algorithm;
		ret.handle = ++crypto_open_count;
	} else {
		ret.algorithm = CRYPTO_NONE;
	}
	return ret;
}

void crypto_close(crypto_session_handle_t *handle)
{
	if (!crypto_session_handle_valid(*handle))
		return;
	crypto_open_count--;
	handle->handle = 0;
	keystore_close(&handle->keystore_handle);
}

bool crypto_signature_check(crypto_session_handle_t handle, uint8_t key_index, const uint8_t *signature,
			    const uint8_t *message, size_t message_size)
{
	uint8_t key[64];
	size_t keylen = 0;

	if (crypto_session_handle_valid(handle))
		keylen = keystore_get_key(handle.keystore_handle, key_index, key, sizeof(key));
	if (keylen == 0)
		return false;

	switch (handle.algorithm) {
	case CRYPTO_ED25519:
		return keylen == 32 && crypto_ed25519_check(signature, key, message, message_size) == 0;
	default:
		return false;
	}
}
