/**
 * @file tr31_crypto.c
 *
 * Copyright (c) 2020, 2021 ono//connect
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "tr31_crypto.h"
#include "tr31_config.h"
#include "tr31.h"

#include "crypto_tdes.h"
#include "crypto_aes.h"
#include "crypto_mem.h"

#include <string.h>

#define TR31_KBEK_VARIANT_XOR (0x45)
#define TR31_KBAK_VARIANT_XOR (0x4D)

// see TR-31:2018, section 5.3.2.1
static const uint8_t tr31_derive_kbek_tdes2_input[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 };
static const uint8_t tr31_derive_kbek_tdes3_input[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0 };
static const uint8_t tr31_derive_kbak_tdes2_input[] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80 };
static const uint8_t tr31_derive_kbak_tdes3_input[] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0xC0 };

// see TR-31:2018, section 5.3.2.3
static const uint8_t tr31_derive_kbek_aes128_input[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80 };
static const uint8_t tr31_derive_kbek_aes192_input[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0 };
static const uint8_t tr31_derive_kbek_aes256_input[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00 };
static const uint8_t tr31_derive_kbak_aes128_input[] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80 };
static const uint8_t tr31_derive_kbak_aes192_input[] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0 };
static const uint8_t tr31_derive_kbak_aes256_input[] = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00 };

int tr31_tdes_verify_cbcmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	const void* mac_verify,
	size_t mac_verify_len
)
{
	int r;
	uint8_t mac[DES_CBCMAC_SIZE];

	if (mac_verify_len > sizeof(mac)) {
		return 1;
	}

	r = crypto_tdes_cbcmac(key, key_len, buf, buf_len, mac);
	if (r) {
		return r;
	}

	r = crypto_memcmp_s(mac, mac_verify, mac_verify_len);

	crypto_cleanse(mac, sizeof(mac));
	return r;
}

int tr31_tdes_verify_cmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	const void* cmac_verify,
	size_t cmac_verify_len
)
{
	int r;
	uint8_t cmac[DES_CMAC_SIZE];

	r = crypto_tdes_cmac(key, key_len, buf, buf_len, cmac);
	if (r) {
		return r;
	}

	r = crypto_memcmp_s(cmac, cmac_verify, cmac_verify_len);

	crypto_cleanse(cmac, sizeof(cmac));
	return r;
}

int tr31_tdes_kbpk_variant(const void* kbpk, size_t kbpk_len, void* kbek, void* kbak)
{
	const uint8_t* kbpk_buf = kbpk;
	uint8_t* kbek_buf = kbek;
	uint8_t* kbak_buf = kbak;

	if (!kbpk || !kbek || !kbak) {
		return -1;
	}
	if (kbpk_len != TDES2_KEY_SIZE && kbpk_len != TDES3_KEY_SIZE) {
		return TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
	}

	for (size_t i = 0; i < kbpk_len; ++i) {
		kbek_buf[i] = kbpk_buf[i] ^ TR31_KBEK_VARIANT_XOR;
		kbak_buf[i] = kbpk_buf[i] ^ TR31_KBAK_VARIANT_XOR;
	}

	return 0;
}

int tr31_tdes_kbpk_derive(const void* kbpk, size_t kbpk_len, void* kbek, void* kbak)
{
	int r;
	uint8_t kbxk_input[8];

	if (!kbpk || !kbek || !kbak) {
		return -1;
	}
	if (kbpk_len != TDES2_KEY_SIZE && kbpk_len != TDES3_KEY_SIZE) {
		return TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
	}

	// See TR-31:2018, section 5.3.2.1
	// CMAC uses subkey and message input to output derived key material of
	// cipher block length.
	// Message input is as described in TR-31:2018, section 5.3.2.1, table 1

	// populate key block encryption key derivation input
	switch (kbpk_len) {
		case TDES2_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbek_tdes2_input, sizeof(tr31_derive_kbek_tdes2_input));
			break;

		case TDES3_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbek_tdes3_input, sizeof(tr31_derive_kbek_tdes3_input));
			break;

		default:
			return -2;
	}

	// derive key block encryption key
	for (size_t kbek_len = 0; kbek_len < kbpk_len; kbek_len += DES_BLOCK_SIZE) {
		// TDES CMAC creates key material of size DES_BLOCK_SIZE
		r = crypto_tdes_cmac(kbpk, kbpk_len, kbxk_input, sizeof(kbxk_input), kbek + kbek_len);
		if (r) {
			// internal error
			return r;
		}

		// increment key derivation input counter
		kbxk_input[0]++;
	}

	// populate key block authentication key derivation input
	switch (kbpk_len) {
		case TDES2_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbak_tdes2_input, sizeof(tr31_derive_kbak_tdes2_input));
			break;

		case TDES3_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbak_tdes3_input, sizeof(tr31_derive_kbak_tdes3_input));
			break;

		default:
			return -3;
	}

	// derive key block authentication key
	for (size_t kbak_len = 0; kbak_len < kbpk_len; kbak_len += DES_BLOCK_SIZE) {
		// TDES CMAC creates key material of size DES_BLOCK_SIZE
		r = crypto_tdes_cmac(kbpk, kbpk_len, kbxk_input, sizeof(kbxk_input), kbak + kbak_len);
		if (r) {
			// internal error
			return r;
		}

		// increment key derivation input counter
		kbxk_input[0]++;
	}

	return 0;
}

int tr31_aes_verify_cmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	const void* cmac_verify,
	size_t cmac_verify_len
)
{
	int r;
	uint8_t cmac[AES_CMAC_SIZE];

	r = crypto_aes_cmac(key, key_len, buf, buf_len, cmac);
	if (r) {
		return r;
	}

	r = crypto_memcmp_s(cmac, cmac_verify, cmac_verify_len);

	crypto_cleanse(cmac, sizeof(cmac));
	return r;
}

int tr31_aes_kbpk_derive(const void* kbpk, size_t kbpk_len, void* kbek, void* kbak)
{
	int r;
	uint8_t kbxk_input[8];

	if (!kbpk || !kbek || !kbak) {
		return -1;
	}
	if (kbpk_len != AES128_KEY_SIZE &&
		kbpk_len != AES192_KEY_SIZE &&
		kbpk_len != AES256_KEY_SIZE
	) {
		return TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
	}

	// See TR-31:2018, section 5.3.2.3
	// CMAC uses subkey and message input to output derived key material of
	// cipher block length.
	// Message input is as described in TR-31:2018, section 5.3.2.3, table 2

	// populate key block encryption key derivation input
	memset(kbxk_input, 0, sizeof(kbxk_input));
	switch (kbpk_len) {
		case AES128_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbek_aes128_input, sizeof(tr31_derive_kbek_aes128_input));
			break;

		case AES192_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbek_aes192_input, sizeof(tr31_derive_kbek_aes192_input));
			break;

		case AES256_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbek_aes256_input, sizeof(tr31_derive_kbek_aes256_input));
			break;

		default:
			return -2;
	}

	// derive key block encryption key
	for (size_t kbek_len = 0; kbek_len < kbpk_len; kbek_len += AES_BLOCK_SIZE) {
		// AES CMAC creates key material of size AES_BLOCK_SIZE

		// see TR-31:2018, section 5.3.2.3
		// for AES-192 key derivation, use the leftmost 8 bytes of the
		// second CMAC block
		if (kbpk_len - kbek_len < AES_BLOCK_SIZE) {
			uint8_t cmac[AES_BLOCK_SIZE];

			r = crypto_aes_cmac(kbpk, kbpk_len, kbxk_input, sizeof(kbxk_input), cmac);
			if (r) {
				// internal error
				return r;
			}

			memcpy(kbek + kbek_len, cmac, kbpk_len - kbek_len);
			crypto_cleanse(cmac, sizeof(cmac));
		} else {
			r = crypto_aes_cmac(kbpk, kbpk_len, kbxk_input, sizeof(kbxk_input), kbek + kbek_len);
			if (r) {
				// internal error
				return r;
			}
		}

		// increment key derivation input counter
		kbxk_input[0]++;
	}

	// populate key block authentication key derivation input
	switch (kbpk_len) {
		case AES128_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbak_aes128_input, sizeof(tr31_derive_kbak_aes128_input));
			break;

		case AES192_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbak_aes192_input, sizeof(tr31_derive_kbak_aes192_input));
			break;

		case AES256_KEY_SIZE:
			memcpy(kbxk_input, tr31_derive_kbak_aes256_input, sizeof(tr31_derive_kbak_aes256_input));
			break;

		default:
			return -3;
	}

	// derive key block authentication key
	for (size_t kbak_len = 0; kbak_len < kbpk_len; kbak_len += AES_BLOCK_SIZE) {
		// AES CMAC creates key material of size AES_BLOCK_SIZE

		// see TR-31:2018, section 5.3.2.3
		// for AES-192 key derivation, use the leftmost 8 bytes of the
		// second CMAC block
		if (kbpk_len - kbak_len < AES_BLOCK_SIZE) {
			uint8_t cmac[AES_BLOCK_SIZE];

			r = crypto_aes_cmac(kbpk, kbpk_len, kbxk_input, sizeof(kbxk_input), cmac);
			if (r) {
				// internal error
				return r;
			}

			memcpy(kbak + kbak_len, cmac, kbpk_len - kbak_len);
			crypto_cleanse(cmac, sizeof(cmac));
		} else {
			r = crypto_aes_cmac(kbpk, kbpk_len, kbxk_input, sizeof(kbxk_input), kbak + kbak_len);
			if (r) {
				// internal error
				return r;
			}
		}

		// increment key derivation input counter
		kbxk_input[0]++;
	}

	return 0;
}
