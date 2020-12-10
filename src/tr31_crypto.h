/**
 * @file tr31_crypto.h
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#ifndef LIBTR31_CRYPTO_H
#define LIBTR31_CRYPTO_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define DES_BLOCK_SIZE (8) ///< DES block size
#define DES_KEY_SIZE (8) ///< DES key size
#define TDES2_KEY_SIZE (DES_KEY_SIZE * 2) ///< Double length triple DES key size
#define TDES3_KEY_SIZE (DES_KEY_SIZE * 3) ///< Triple length triple DES key size
#define DES_CIPHERTEXT_LENGTH(plen) (((plen) + DES_BLOCK_SIZE-1) & ~(DES_BLOCK_SIZE-1)) ///< DES ciphertext length at next block boundary

#define TR31_DES_KEY_UNDER_DES_PAYLOAD_LEN (DES_CIPHERTEXT_LENGTH(2 + DES_KEY_SIZE) * 2) ///< 2-byte length + DES key + DES padding, in ASCII hex
#define TR31_TDES2_KEY_UNDER_DES_PAYLOAD_LEN (DES_CIPHERTEXT_LENGTH(2 + TDES2_KEY_SIZE) * 2) ///< 2-byte length + TDES2 key + DES padding, in ASCII hex
#define TR31_TDES3_KEY_UNDER_DES_PAYLOAD_LEN (DES_CIPHERTEXT_LENGTH(2 + TDES3_KEY_SIZE) * 2) ///< 2-byte length + TDES3 key + DES padding, in ASCII hex

__END_DECLS

#endif
