/**
 * @file tr31_crypto.c
 * @brief TR-31 cryptography helper functions
 *
 * Copyright 2020-2023 Leon Lynch
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

#include <stdint.h>
#include <string.h>

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h> // For htons and friends
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

#define TR31_KBEK_VARIANT_XOR (0x45)
#define TR31_KBAK_VARIANT_XOR (0x4D)

// Key derivation input data
// See ANSI X9.143:2021, 7.2.1.1, table 24
// See ANSI X9.143:2021, 7.2.2.1, table 25
// See ISO 20038:2017, section 6.3, table 1
struct tr31_derivation_data_t {
	uint8_t counter; // Counter that is incremented for each block of keying material
	uint16_t key_usage; // Usage of derived key (not TR-31 key usage)
	uint8_t separator; // Separator; must be zero
	uint16_t algorithm; // Algorithm of derived key (not TR-31 key algorithm)
	uint16_t length; // Length of derived key in bits
} __attribute__((packed));

enum tr31_derivation_key_usage_t {
	TR31_DERIVATION_KEY_USAGE_ENCRYPTION_CBC = 0x0000,
	TR31_DERIVATION_KEY_USAGE_MAC = 0x0001,
	TR31_DERIVATION_KEY_USAGE_ENCRYPTION_CTR = 0x0002,
};

enum tr31_derivation_algorithm_t {
	TR31_DERIVATION_ALGORITHM_2TDEA = 0x0000,
	TR31_DERIVATION_ALGORITHM_3TDEA = 0x0001,
	TR31_DERIVATION_ALGORITHM_AES128 = 0x0002,
	TR31_DERIVATION_ALGORITHM_AES192 = 0x0003,
	TR31_DERIVATION_ALGORITHM_AES256 = 0x0004,
};

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
	struct tr31_derivation_data_t kbxk_input;

	if (!kbpk || !kbek || !kbak) {
		return -1;
	}
	if (kbpk_len != TDES2_KEY_SIZE && kbpk_len != TDES3_KEY_SIZE) {
		return TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
	}

	// See ANSI X9.143:2021, section 7.2.2
	// CMAC uses subkey and message input to output derived key material of
	// cipher block length.
	// Message input is as described in ANSI X9.143:2021, 7.2.2.1, table 25

	// Populate key block encryption key derivation input
	memset(&kbxk_input, 0, sizeof(kbxk_input));
	kbxk_input.counter = 1;
	kbxk_input.key_usage = htons(TR31_DERIVATION_KEY_USAGE_ENCRYPTION_CBC);
	kbxk_input.algorithm = htons(kbpk_len / 24); // This intentionally corresponds with tr31_derivation_algorithm_t
	kbxk_input.length = htons(kbpk_len * 8);

	// Derive key block encryption key
	for (size_t kbek_len = 0; kbek_len < kbpk_len; kbek_len += DES_BLOCK_SIZE) {
		// TDES CMAC creates key material of size DES_BLOCK_SIZE
		r = crypto_tdes_cmac(kbpk, kbpk_len, &kbxk_input, sizeof(kbxk_input), kbek + kbek_len);
		if (r) {
			// Internal error
			return r;
		}

		// Increment key derivation input counter
		kbxk_input.counter++;
	}

	// Populate key block authentication key derivation input
	memset(&kbxk_input, 0, sizeof(kbxk_input));
	kbxk_input.counter = 1;
	kbxk_input.key_usage = htons(TR31_DERIVATION_KEY_USAGE_MAC);
	kbxk_input.algorithm = htons(kbpk_len / 24); // This intentionally corresponds with tr31_derivation_algorithm_t
	kbxk_input.length = htons(kbpk_len * 8);

	// Derive key block authentication key
	for (size_t kbak_len = 0; kbak_len < kbpk_len; kbak_len += DES_BLOCK_SIZE) {
		// TDES CMAC creates key material of size DES_BLOCK_SIZE
		r = crypto_tdes_cmac(kbpk, kbpk_len, &kbxk_input, sizeof(kbxk_input), kbak + kbak_len);
		if (r) {
			// Internal error
			return r;
		}

		// Increment key derivation input counter
		kbxk_input.counter++;
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

int tr31_aes_kbpk_derive(
	const void* kbpk,
	size_t kbpk_len,
	enum tr31_aes_mode_t mode,
	void* kbek,
	void* kbak
)
{
	int r;
	struct tr31_derivation_data_t kbxk_input;

	if (!kbpk || !kbek || !kbak) {
		return -1;
	}
	if (mode != TR31_AES_MODE_CBC &&
		mode != TR31_AES_MODE_CTR
	) {
		return -2;
	}
	if (kbpk_len != AES128_KEY_SIZE &&
		kbpk_len != AES192_KEY_SIZE &&
		kbpk_len != AES256_KEY_SIZE
	) {
		return TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
	}

	// See ANSI X9.143:2021, section 7.2.1
	// CMAC uses subkey and message input to output derived key material of
	// cipher block length.
	// Message input is as described in ANSI X9.143:2021, 7.2.1.1, table 24,
	// and ISO 20038:2017, section 6.3, table 1

	// Populate key block encryption key derivation input
	memset(&kbxk_input, 0, sizeof(kbxk_input));
	kbxk_input.counter = 1;
	if (mode == TR31_AES_MODE_CBC) {
		kbxk_input.key_usage = htons(TR31_DERIVATION_KEY_USAGE_ENCRYPTION_CBC);
	} else if (mode == TR31_AES_MODE_CTR) {
		kbxk_input.key_usage = htons(TR31_DERIVATION_KEY_USAGE_ENCRYPTION_CTR);
	} else {
		return -3;
	}
	kbxk_input.algorithm = htons(kbpk_len / 8); // This intentionally corresponds with tr31_derivation_algorithm_t
	kbxk_input.length = htons(kbpk_len * 8);

	// Derive key block encryption key
	for (size_t kbek_len = 0; kbek_len < kbpk_len; kbek_len += AES_BLOCK_SIZE) {
		// AES CMAC creates key material of size AES_BLOCK_SIZE
		if (kbpk_len - kbek_len < AES_BLOCK_SIZE) {
			uint8_t cmac[AES_BLOCK_SIZE];

			// See ANSI X9.143:2021, 7.2.1.1, figure 5
			// For AES-192 key derivation, use the leftmost 8 bytes of the
			// second CMAC block

			r = crypto_aes_cmac(kbpk, kbpk_len, &kbxk_input, sizeof(kbxk_input), cmac);
			if (r) {
				// Internal error
				return r;
			}

			memcpy(kbek + kbek_len, cmac, kbpk_len - kbek_len);
			crypto_cleanse(cmac, sizeof(cmac));
		} else {
			// See ANSI X9.143:2021, 7.2.1.1, figure 4 & 6
			r = crypto_aes_cmac(kbpk, kbpk_len, &kbxk_input, sizeof(kbxk_input), kbek + kbek_len);
			if (r) {
				// Internal error
				return r;
			}
		}

		// Increment key derivation input counter
		kbxk_input.counter++;
	}

	// Populate key block authentication key derivation input
	memset(&kbxk_input, 0, sizeof(kbxk_input));
	kbxk_input.counter = 1;
	kbxk_input.key_usage = htons(TR31_DERIVATION_KEY_USAGE_MAC);
	kbxk_input.algorithm = htons(kbpk_len / 8); // This intentionally corresponds with tr31_derivation_algorithm_t
	kbxk_input.length = htons(kbpk_len * 8);

	// Derive key block authentication key
	for (size_t kbak_len = 0; kbak_len < kbpk_len; kbak_len += AES_BLOCK_SIZE) {
		// AES CMAC creates key material of size AES_BLOCK_SIZE
		if (kbpk_len - kbak_len < AES_BLOCK_SIZE) {
			uint8_t cmac[AES_BLOCK_SIZE];

			// See ANSI X9.143:2021, 7.2.1.1, figure 5
			// For AES-192 key derivation, use the leftmost 8 bytes of the
			// second CMAC block

			r = crypto_aes_cmac(kbpk, kbpk_len, &kbxk_input, sizeof(kbxk_input), cmac);
			if (r) {
				// Internal error
				return r;
			}

			memcpy(kbak + kbak_len, cmac, kbpk_len - kbak_len);
			crypto_cleanse(cmac, sizeof(cmac));
		} else {
			// See ANSI X9.143:2021, 7.2.1.1, figure 4 & 6
			r = crypto_aes_cmac(kbpk, kbpk_len, &kbxk_input, sizeof(kbxk_input), kbak + kbak_len);
			if (r) {
				// Internal error
				return r;
			}
		}

		// Increment key derivation input counter
		kbxk_input.counter++;
	}

	return 0;
}
