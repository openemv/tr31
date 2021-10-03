/**
 * @file tr31_crypto.h
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

#ifndef LIBTR31_CRYPTO_H
#define LIBTR31_CRYPTO_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define DES_BLOCK_SIZE (8) ///< DES block size in bytes
#define DES_KEY_SIZE (8) ///< DES key size in bytes
#define TDES2_KEY_SIZE (DES_KEY_SIZE * 2) ///< Double length triple DES key size in bytes
#define TDES3_KEY_SIZE (DES_KEY_SIZE * 3) ///< Triple length triple DES key size in bytes
#define DES_CIPHERTEXT_LENGTH(plen) (((plen) + DES_BLOCK_SIZE-1) & ~(DES_BLOCK_SIZE-1)) ///< DES ciphertext length at next block boundary
#define DES_MAC_SIZE (DES_BLOCK_SIZE / 2)

#define AES_BLOCK_SIZE (16) ///< AES block size in bytes
#define AES128_KEY_SIZE (16) ///< AES-128 key size in bytes
#define AES192_KEY_SIZE (24) ///< AES-192 key size in bytes
#define AES256_KEY_SIZE (32) ///< AES-256 key size in bytes
#define AES_CIPHERTEXT_LENGTH(plen) (((plen) + AES_BLOCK_SIZE-1) & ~(AES_BLOCK_SIZE-1)) ///< AES ciphertext length at next block boundary

#define TR31_DES_KEY_UNDER_DES_LENGTH DES_CIPHERTEXT_LENGTH(2 + DES_KEY_SIZE) ///< 2-byte length + DES key + DES padding, in bytes
#define TR31_DES_KEY_UNDER_AES_LENGTH AES_CIPHERTEXT_LENGTH(2 + DES_KEY_SIZE) ///< 2-byte length + DES key + AES padding, in bytes

#define TR31_TDES2_KEY_UNDER_DES_LENGTH DES_CIPHERTEXT_LENGTH(2 + TDES2_KEY_SIZE) ///< 2-byte length + TDES2 key + DES padding, in bytes
#define TR31_TDES2_KEY_UNDER_AES_LENGTH AES_CIPHERTEXT_LENGTH(2 + TDES2_KEY_SIZE) ///< 2-byte length + TDES2 key + AES padding, in bytes

#define TR31_TDES3_KEY_UNDER_DES_LENGTH DES_CIPHERTEXT_LENGTH(2 + TDES3_KEY_SIZE) ///< 2-byte length + TDES3 key + DES padding, in bytes
#define TR31_TDES3_KEY_UNDER_AES_LENGTH AES_CIPHERTEXT_LENGTH(2 + TDES3_KEY_SIZE) ///< 2-byte length + TDES3 key + AES padding, in bytes

#define TR31_AES128_KEY_UNDER_AES_LENGTH AES_CIPHERTEXT_LENGTH(2 + AES128_KEY_SIZE) ///< 2-byte length + AES-128 key + AES padding, in bytes
#define TR31_AES192_KEY_UNDER_AES_LENGTH AES_CIPHERTEXT_LENGTH(2 + AES192_KEY_SIZE) ///< 2-byte length + AES-192 key + AES padding, in bytes
#define TR31_AES256_KEY_UNDER_AES_LENGTH AES_CIPHERTEXT_LENGTH(2 + AES256_KEY_SIZE) ///< 2-byte length + AES-256 key + AES padding, in bytes

/**
 * Encrypt using TDES ECB
 * @param key Key
 * @param key_len Length of key in bytes
 * @param plaintext Plaintext of length @ref DES_BLOCK_SIZE to encrypt
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_tdes_encrypt_ecb(const void* key, size_t key_len, const void* plaintext, void* ciphertext);

/**
 * Decrypt using TDES ECB
 * @param key Key
 * @param key_len Length of key in bytes
 * @param ciphertext Ciphertext of length @ref DES_BLOCK_SIZE to decrypt
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_tdes_decrypt_ecb(const void* key, size_t key_len, const void* ciphertext, void* plaintext);

/**
 * Encrypt using TDES CBC
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_tdes_encrypt_cbc(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Decrypt using TDES CBC
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_tdes_decrypt_cbc(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext);

/**
 * Compute TDES CBC-MAC
 * @see ISO 9797-1:2011 MAC algorithm 1
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input buffer
 * @param len Length of input buffer in bytes
 * @param mac CBC-MAC output of length @ref DES_MAC_SIZE
 * @return Zero for success. Non-zero for error.
 */
int tr31_tdes_cbcmac(const void* key, size_t key_len, const void* buf, size_t len, void* mac);

/**
 * Verify using TDES CBC-MAC
 * @see ISO 9797-1:2011 MAC algorithm 1
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input buffer
 * @param len Length of input buffer in bytes
 * @param mac_verify CBC-MAC of length @ref DES_MAC_SIZE to verify
 * @return Zero for success. Non-zero for verification failure.
 */
int tr31_tdes_verify_cbcmac(const void* key, size_t key_len, const void* buf, size_t len, const void* mac_verify);

/**
 * Compute TDES CMAC
 * @remark See NIST SP 800-38B, section 6.2
 * @remark See ISO 9797-1:2011 MAC algorithm 5
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input buffer
 * @param len Length of input buffer in bytes
 * @param cmac CMAC output of length @ref DES_BLOCK_SIZE
 * @return Zero for success. Non-zero for error.
 */
int tr31_tdes_cmac(const void* key, size_t key_len, const void* buf, size_t len, void* cmac);

/**
 * Verify using TDES CMAC
 * @remark See NIST SP 800-38B, section 6.3
 * @remark See ISO 9797-1:2011 MAC algorithm 5
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input buffer to verify
 * @param len Length of input buffer in bytes
 * @param cmac_verify CMAC of length @ref DES_BLOCK_SIZE to verify
 * @return Zero for success. Non-zero for verification failure.
 */
int tr31_tdes_verify_cmac(const void* key, size_t key_len, const void* buf, size_t len, const void* cmac_verify);

/**
 * Output TDES key block encryption key (KBEK) variant and key block authentication key (KBAK) variant from key block protection key (KBPK)
 * @param kbpk Key block protection key
 * @param kbpk_len Length of key block protection key in bytes
 * @param kbek Key block encryption key output
 * @param kbak Key block authentication key output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. @see #tr31_error_t
 */
int tr31_tdes_kbpk_variant(const void* kbpk, size_t kbpk_len, void* kbek, void* kbak);

/**
 * Derive TDES key block encryption key (KBEK) and key block authentication key (KBAK) from key block protection key (KBPK)
 * @param kbpk Key block protection key
 * @param kbpk_len Length of key block protection key in bytes
 * @param kbek Key block encryption key output
 * @param kbak Key block authentication key output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. @see #tr31_error_t
 */
int tr31_tdes_kbpk_derive(const void* kbpk, size_t kbpk_len, void* kbek, void* kbak);

/**
 * Compute TDES Key Check Value (KCV)
 * @param key Key
 * @param key_len Length of key in bytes
 * @param kcv Key Check Value output of 3 bytes
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_tdes_kcv(const void* key, size_t key_len, void* kcv);

/**
 * Encrypt using AES ECB
 * @param key Key
 * @param key_len Length of key in bytes
 * @param plaintext Plaintext of length @ref AES_BLOCK_SIZE to encrypt
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_aes_encrypt_ecb(const void* key, size_t key_len, const void* plaintext, void* ciphertext);

/**
 * Decrypt using AES ECB
 * @param key Key
 * @param key_len Length of key in bytes
 * @param ciphertext Ciphertext of length @ref AES_BLOCK_SIZE to decrypt
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_aes_decrypt_ecb(const void* key, size_t key_len, const void* ciphertext, void* plaintext);

/**
 * Encrypt using AES CBC
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref AES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_aes_encrypt_cbc(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Decrypt using AES CBC
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref AES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_aes_decrypt_cbc(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext);

/**
 * Compute AES CMAC
 * @remark See NIST SP 800-38B, section 6.2
 * @remark See ISO 9797-1:2011 MAC algorithm 5
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input buffer
 * @param len Length of input buffer in bytes
 * @param cmac CMAC output of length @ref AES_BLOCK_SIZE
 * @return Zero for success. Non-zero for error.
 */
int tr31_aes_cmac(const void* key, size_t key_len, const void* buf, size_t len, void* cmac);

/**
 * Verify using AES CMAC
 * @remark See NIST SP 800-38B, section 6.3
 * @remark See ISO 9797-1:2011 MAC algorithm 5
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input buffer to verify
 * @param len Length of input buffer in bytes
 * @param cmac_verify CMAC of length @ref AES_BLOCK_SIZE to verify
 * @return Zero for success. Non-zero for verification failure.
 */
int tr31_aes_verify_cmac(const void* key, size_t key_len, const void* buf, size_t len, const void* cmac_verify);

/**
 * Derive AES key block encryption key (KBEK) and key block authentication key (KBAK) from key block protection key (KBPK)
 * @param kbpk Key block protection key
 * @param kbpk_len Length of key block protection key in bytes
 * @param kbek Key block encryption key output
 * @param kbak Key block authentication key output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. @see #tr31_error_t
 */
int tr31_aes_kbpk_derive(const void* kbpk, size_t kbpk_len, void* kbek, void* kbak);

/**
 * Compute AES Key Check Value (KCV)
 * @param key Key
 * @param key_len Length of key in bytes
 * @param kcv Key Check Value output of 3 bytes
 * @return Zero for success. Less than zero for internal error.
 */
int tr31_aes_kcv(const void* key, size_t key_len, void* kcv);

/**
 * Cleanse buffer at pointer
 * @param ptr Pointer to buffer
 * @param len Length of buffer in bytes
 */
void tr31_cleanse(void* ptr, size_t len);

__END_DECLS

#endif
