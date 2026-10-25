/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_lms.h
* Summary: LMS / HSS stateful hash-based signatures (RFC 8554, NIST SP 800-208).
*
*****************************************************************************/

#ifndef NOXTLS_LMS_H_
#define NOXTLS_LMS_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "mdigest/noxtls_sha.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Overview
 * --------
 * LM-OTS, LMS and HSS (RFC 8554) with every parameter set of RFC 8554 and
 * NIST SP 800-208: LMS heights H5..H25 and LM-OTS Winternitz W1..W8 for the
 * hash functions SHA-256, SHA-256/192, SHAKE256/256 and SHAKE256/192 (the
 * SHAKE sets need NOXTLS_FEATURE_SHA3).
 *
 * Verification (noxtls_hss_verify*, noxtls_lms_verify) is stateless, uses no
 * heap and a constant amount of stack (about 1.0-1.3 KiB on Cortex-M4,
 * measured), and can stream the message (init/update/final).
 *
 * Signing is STATEFUL.  Every LM-OTS key (one leaf of one LMS tree) may sign
 * only once.  The library enforces this through the key state contract below:
 *
 *  1. The private key is a fixed NOXTLS_HSS_PRIVATE_KEY_LEN byte blob that
 *     holds the parameter set, I, SEED, the root T[1] and a 64-bit counter =
 *     the first global signature index that has NOT been reserved yet.  It is
 *     protected by a checksum (corruption is detected, it is not a MAC).
 *     Layout (big-endian): "NXHS" | version 1 | format | L | 0 |
 *     8 x (u32 lms_type, u32 ots_type) @8 | u64 counter @72 | I @80 |
 *     SEED @96 (n bytes, zero padded to 32) | T[1] @128 (padded to 32) |
 *     first 8 bytes of SHA-256(bytes 0..159) @160.
 *  2. noxtls_hss_key_load() loads the blob into a noxtls_hss_key_t working
 *     key.  It requires a persistence callback; signing is impossible without
 *     one.
 *  3. Before a signature index is used, it must be covered by the persisted
 *     counter.  When the in-RAM reservation is used up, noxtls_hss_sign()
 *     serializes the blob with counter = next index + reserve (default
 *     reserve 1), calls the callback, and continues only if it returns
 *     NOXTLS_RETURN_SUCCESS.  On any callback error nothing is signed, the
 *     output buffer is not touched and the callback's error code is returned.
 *     The callback must return success only once the blob is durably stored
 *     (use two slots / atomic replace: a torn write is detected by the
 *     checksum on the next load and the key then refuses to load).
 *  4. The index is consumed in RAM before any signature material is
 *     computed; any failure after that point burns the index (never reuses
 *     it).  Each produced signature is verified against the public key before
 *     it is released (can be disabled with NOXTLS_HSS_KEY_NO_SELF_VERIFY).
 *  5. noxtls_hss_key_reserve() / noxtls_hss_key_set_reserve() persist several
 *     indices at once (fewer flash writes).  Reserved but unused indices are
 *     lost if the device resets: that is safe, never reuse.
 *  6. Exhausted keys return NOXTLS_RETURN_KEY_EXHAUSTED;
 *     noxtls_hss_key_remaining() reports the signatures left.
 *  7. Never restore an older copy of the private key blob (backup/rollback):
 *     that reuses one-time keys.  A reused workspace whose index is ahead of
 *     the blob counter is reported as a rollback (NOXTLS_RETURN_BAD_DATA).
 *
 * HSS lower-level trees are derived deterministically from the parent's I and
 * SEED and the parent leaf index (H(I || u32(q) || u16(0xFFFE/0xFFFF) || 0xFF
 * || SEED), the hash-sigs convention), and the LM-OTS randomizer C is
 * pseudo-random (RFC 8554 Appendix A style: H(I || u32(q) || u16(0xFFFD) ||
 * 0xFF || SEED)).  Re-signing a child public key after a reload therefore
 * reproduces the same message and signature, so the whole HSS state is one
 * 64-bit counter.
 *
 * Low-RAM tree traversal: each LMS tree is split into sublevels of height
 * subtree_height (s).  The workspace keeps, for every sublevel, the active
 * subtree containing the current authentication path plus the next one,
 * which is built incrementally (one leaf per signature and sublevel).  Cost
 * per signature is about ceil(h/s) leaf computations; memory is about
 * 2 * ceil(h/s) * 2^(s+1) * n bytes per tree (noxtls_hss_workspace_len()).
 * s = h keeps the whole tree (fastest, largest).  The workspace holds only
 * public data, so it may be kept across resets (e.g. retained RAM) and passed
 * back with NOXTLS_HSS_LOAD_REUSE_WORKSPACE; otherwise noxtls_hss_key_load()
 * recomputes it, which costs about the same as key generation (2^h leaf
 * computations per level).
 */

/* RFC 8554 / SP 800-208 LMS typecodes (IANA "LMS Algorithm Registry"). */
#define NOXTLS_LMS_TYPE_SHA256_M32_H5    0x00000005U
#define NOXTLS_LMS_TYPE_SHA256_M32_H10   0x00000006U
#define NOXTLS_LMS_TYPE_SHA256_M32_H15   0x00000007U
#define NOXTLS_LMS_TYPE_SHA256_M32_H20   0x00000008U
#define NOXTLS_LMS_TYPE_SHA256_M32_H25   0x00000009U
#define NOXTLS_LMS_TYPE_SHA256_M24_H5    0x0000000AU
#define NOXTLS_LMS_TYPE_SHA256_M24_H10   0x0000000BU
#define NOXTLS_LMS_TYPE_SHA256_M24_H15   0x0000000CU
#define NOXTLS_LMS_TYPE_SHA256_M24_H20   0x0000000DU
#define NOXTLS_LMS_TYPE_SHA256_M24_H25   0x0000000EU
#define NOXTLS_LMS_TYPE_SHAKE_M32_H5     0x0000000FU
#define NOXTLS_LMS_TYPE_SHAKE_M32_H10    0x00000010U
#define NOXTLS_LMS_TYPE_SHAKE_M32_H15    0x00000011U
#define NOXTLS_LMS_TYPE_SHAKE_M32_H20    0x00000012U
#define NOXTLS_LMS_TYPE_SHAKE_M32_H25    0x00000013U
#define NOXTLS_LMS_TYPE_SHAKE_M24_H5     0x00000014U
#define NOXTLS_LMS_TYPE_SHAKE_M24_H10    0x00000015U
#define NOXTLS_LMS_TYPE_SHAKE_M24_H15    0x00000016U
#define NOXTLS_LMS_TYPE_SHAKE_M24_H20    0x00000017U
#define NOXTLS_LMS_TYPE_SHAKE_M24_H25    0x00000018U

/* RFC 8554 / SP 800-208 LM-OTS typecodes. */
#define NOXTLS_LMOTS_TYPE_SHA256_N32_W1  0x00000001U
#define NOXTLS_LMOTS_TYPE_SHA256_N32_W2  0x00000002U
#define NOXTLS_LMOTS_TYPE_SHA256_N32_W4  0x00000003U
#define NOXTLS_LMOTS_TYPE_SHA256_N32_W8  0x00000004U
#define NOXTLS_LMOTS_TYPE_SHA256_N24_W1  0x00000005U
#define NOXTLS_LMOTS_TYPE_SHA256_N24_W2  0x00000006U
#define NOXTLS_LMOTS_TYPE_SHA256_N24_W4  0x00000007U
#define NOXTLS_LMOTS_TYPE_SHA256_N24_W8  0x00000008U
#define NOXTLS_LMOTS_TYPE_SHAKE_N32_W1   0x00000009U
#define NOXTLS_LMOTS_TYPE_SHAKE_N32_W2   0x0000000AU
#define NOXTLS_LMOTS_TYPE_SHAKE_N32_W4   0x0000000BU
#define NOXTLS_LMOTS_TYPE_SHAKE_N32_W8   0x0000000CU
#define NOXTLS_LMOTS_TYPE_SHAKE_N24_W1   0x0000000DU
#define NOXTLS_LMOTS_TYPE_SHAKE_N24_W2   0x0000000EU
#define NOXTLS_LMOTS_TYPE_SHAKE_N24_W4   0x0000000FU
#define NOXTLS_LMOTS_TYPE_SHAKE_N24_W8   0x00000010U

/** Encoding: bare LMS public key / signature (RFC 8554 section 5). */
#define NOXTLS_LMS_FORMAT_LMS 0U
/** Encoding: HSS public key / signature (RFC 8554 section 6, L-prefixed). */
#define NOXTLS_LMS_FORMAT_HSS 1U

/** Largest number of HSS levels (RFC 8554: 1 <= L <= 8). */
#define NOXTLS_HSS_MAX_LEVELS 8U
/** Size of the serialized private key (see the state contract above). */
#define NOXTLS_HSS_PRIVATE_KEY_LEN 168U
/** Largest LMS signature (SHA-256/SHAKE n = 32, W1, H25). */
#define NOXTLS_LMS_MAX_LMS_SIGNATURE_LEN 9324U
/** Largest HSS public key (L || LMS public key with m = 32). */
#define NOXTLS_HSS_MAX_PUBLIC_KEY_LEN 60U
/** Default sublevel height used when subtree_height is 0. */
#define NOXTLS_HSS_DEFAULT_SUBTREE_HEIGHT 5U

/** noxtls_hss_key_load() flags. */
#define NOXTLS_HSS_LOAD_REUSE_WORKSPACE 0x00000001U /**< Keep a valid workspace from an earlier session. */
#define NOXTLS_HSS_KEY_FAULT_HARDENING  0x00000002U /**< Recompute new child roots twice before signing them. */
#define NOXTLS_HSS_KEY_NO_SELF_VERIFY   0x00000004U /**< Skip verifying each signature before release (not recommended). */

/**
 * HSS / LMS parameter set.  levels = L (1..8); lms_type[i] / ots_type[i] are
 * the typecodes of level i (0 = top).  format NOXTLS_LMS_FORMAT_LMS requires
 * levels == 1.  For key generation all levels must use the same hash function
 * and output length, and each LM-OTS type must match its LMS type's hash.
 */
typedef struct
{
    uint32_t format;
    uint32_t levels;
    uint32_t lms_type[NOXTLS_HSS_MAX_LEVELS];
    uint32_t ots_type[NOXTLS_HSS_MAX_LEVELS];
} noxtls_hss_params_t;

/** Hash context used by LMS (SHA-256 or SHAKE256, n-byte output). */
typedef struct
{
    noxtls_sha_ctx_t sha;
    uint32_t alg;
    uint32_t n;
} noxtls_lms_hash_t;

/**
 * Streaming verification context.  The public key and signature buffers
 * passed to noxtls_hss_verify_init() must stay valid and unchanged until
 * noxtls_hss_verify_final().
 */
typedef struct
{
    noxtls_lms_hash_t msg;
    const uint8_t *lms_pk;
    const uint8_t *lms_sig;
    uint32_t state;
} noxtls_hss_verify_ctx_t;

/**
 * Persistence callback: store private_key (NOXTLS_HSS_PRIVATE_KEY_LEN bytes,
 * contains the secret SEED) durably and return NOXTLS_RETURN_SUCCESS only
 * when that succeeded.  Any other value aborts the signature (fail closed).
 */
typedef noxtls_return_t (*noxtls_hss_persist_fn)(void *user, const uint8_t *private_key, uint32_t private_key_len);

/**
 * Working (in-RAM) signing key.  Contains secrets: release it with
 * noxtls_hss_key_free() (wipes it).  Not thread-safe; serialize calls.
 */
typedef struct
{
    noxtls_hss_params_t params;
    uint8_t id[NOXTLS_HSS_MAX_LEVELS][16];
    uint8_t seed[NOXTLS_HSS_MAX_LEVELS][32];
    uint8_t root[32];
    uint64_t next_index;
    uint64_t reserved_index;
    uint64_t max_index;
    uint32_t reserve;
    uint32_t subtree_height;
    uint32_t flags;
    uint32_t state;
    noxtls_hss_persist_fn persist;
    void *persist_user;
    uint8_t *ws;
    uint32_t ws_len;
    uint32_t ws_owned;
} noxtls_hss_key_t;

/* ---- legacy preset API (RFC 8554 SHA-256 sets with LMOTS_SHA256_N32_W8) --- */

typedef uint32_t noxtls_lms_param_t;
#define NOXTLS_LMS_NONE               ((noxtls_lms_param_t)0U)
#define NOXTLS_LMS_SHA256_M32_H5      ((noxtls_lms_param_t)1U)  /**< LMS (bare), H5 / W8 */
#define NOXTLS_LMS_SHA256_M32_H10     ((noxtls_lms_param_t)2U)  /**< LMS (bare), H10 / W8 */
#define NOXTLS_LMS_SHA256_M32_H15     ((noxtls_lms_param_t)3U)  /**< LMS (bare), H15 / W8 */
#define NOXTLS_HSS_SHA256_M32_H10_D2  ((noxtls_lms_param_t)4U)  /**< HSS L=2, H10/H10, W8 */
#define NOXTLS_HSS_SHA256_M32_H15_D2  ((noxtls_lms_param_t)5U)  /**< HSS L=2, H15/H15, W8 */

#define NOXTLS_LMS_MAX_PUBLIC_KEY_LEN  64U
#define NOXTLS_LMS_MAX_SECRET_KEY_LEN  256u
#define NOXTLS_LMS_MAX_SIGNATURE_LEN   8192u

#if NOXTLS_FEATURE_LMS_HSS

/* ---- parameter sets and sizes ------------------------------------------ */

/**
 * @brief Check that a parameter set is well formed and supported.
 * @param[in] params Parameter set.
 * @param[in] for_signing Non-zero to also apply the key generation / signing
 *            restrictions (same hash and n on every level, total tree height
 *            <= 63).
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_PARAM.
 */
noxtls_return_t noxtls_hss_params_check(const noxtls_hss_params_t *params, uint32_t for_signing);
/** @return Public key length in bytes (24 + n, plus 4 for HSS), 0 if invalid. */
uint32_t noxtls_hss_public_key_len(const noxtls_hss_params_t *params);
/** @return Signature length in bytes, 0 if invalid. */
uint32_t noxtls_hss_signature_len(const noxtls_hss_params_t *params);
/** @return Total number of signatures of a key (2^(h_0 + ... + h_{L-1})), 0 if invalid or > 2^63. */
uint64_t noxtls_hss_max_signatures(const noxtls_hss_params_t *params);
/**
 * @return Workspace bytes needed by noxtls_hss_key_load() for this parameter
 *         set and sublevel height (0 selects NOXTLS_HSS_DEFAULT_SUBTREE_HEIGHT),
 *         or 0 if invalid / larger than 4 GiB.
 */
uint32_t noxtls_hss_workspace_len(const noxtls_hss_params_t *params, uint32_t subtree_height);
/** @return Length of one LMS signature for an LMS / LM-OTS typecode pair, 0 if invalid. */
uint32_t noxtls_lms_type_signature_len(uint32_t lms_type, uint32_t ots_type);

/* ---- verification (stateless) ------------------------------------------- */

/**
 * @brief Verify an LMS (format LMS) or HSS (format HSS) signature.
 *
 * The public key is trusted input and must be exactly the encoded length;
 * the signature is untrusted and parsed strictly (exact length, typecodes
 * equal to the public key's, q < 2^h, Nspk = L - 1).
 *
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid.
 * @return NOXTLS_RETURN_FAILED if the signature is invalid or malformed.
 * @return NOXTLS_RETURN_INVALID_PARAM for a malformed/unsupported public key.
 * @return NOXTLS_RETURN_NULL for missing arguments.
 */
noxtls_return_t noxtls_hss_verify(uint32_t format,
                                  const uint8_t *public_key, uint32_t public_key_len,
                                  const uint8_t *message, uint32_t message_len,
                                  const uint8_t *signature, uint32_t signature_len);
/**
 * @brief Start a streaming verification: parses the signature and verifies
 *        all signed lower-level public keys; the message follows through
 *        noxtls_hss_verify_update().  Same return codes as noxtls_hss_verify().
 */
noxtls_return_t noxtls_hss_verify_init(noxtls_hss_verify_ctx_t *ctx, uint32_t format,
                                       const uint8_t *public_key, uint32_t public_key_len,
                                       const uint8_t *signature, uint32_t signature_len);
noxtls_return_t noxtls_hss_verify_update(noxtls_hss_verify_ctx_t *ctx, const uint8_t *data, uint32_t len);
/** @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED otherwise.  Wipes ctx. */
noxtls_return_t noxtls_hss_verify_final(noxtls_hss_verify_ctx_t *ctx);

/* ---- key generation ---------------------------------------------------- */

/**
 * @brief Generate an LMS / HSS key pair.
 *
 * The top-level tree is derived from I and SEED as in RFC 8554 Appendix A.
 * @param[in] seed SEED (n bytes for the level-0 hash) or NULL for DRBG output.
 * @param[in] id   I (16 bytes) or NULL for DRBG output.
 * @param[out] public_key At least noxtls_hss_public_key_len(params) bytes.
 * @param[out] private_key At least NOXTLS_HSS_PRIVATE_KEY_LEN bytes (counter 0).
 * Cost: 2^h_0 LM-OTS public key computations (e.g. H20/W8 about 9e9 hashes).
 * Stack about 2.1 KiB on Cortex-M4 (measured), no heap.
 */
noxtls_return_t noxtls_hss_keygen(const noxtls_hss_params_t *params,
                                  const uint8_t *seed, const uint8_t *id,
                                  uint8_t *public_key, uint32_t public_key_len,
                                  uint8_t *private_key, uint32_t private_key_len);

/**
 * @brief Read the parameters and the next unreserved index of a private key blob.
 * @param[out] params (may be NULL) @param[out] next_index (may be NULL)
 * @param[out] remaining (may be NULL) signatures left after next_index.
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_BAD_DATA if corrupt.
 */
noxtls_return_t noxtls_hss_private_key_info(const uint8_t *private_key, uint32_t private_key_len,
                                            noxtls_hss_params_t *params, uint64_t *next_index,
                                            uint64_t *remaining);

/* ---- stateful signing ------------------------------------------------------ */

/**
 * @brief Load a private key into a working key (see the state contract).
 * @param[in] workspace Caller workspace (4-byte aligned, at least
 *            noxtls_hss_workspace_len(params, subtree_height) bytes) or NULL
 *            to allocate it with NOXTLS_MALLOC (freed by noxtls_hss_key_free).
 * @param[in] subtree_height Traversal sublevel height s (0 = default 5).
 * @param[in] flags NOXTLS_HSS_LOAD_REUSE_WORKSPACE, NOXTLS_HSS_KEY_FAULT_HARDENING,
 *            NOXTLS_HSS_KEY_NO_SELF_VERIFY.
 * @param[in] persist Mandatory persistence callback.
 * Unless a valid workspace is reused this rebuilds the traversal state
 * (about sum of 2^h_i leaf computations).
 * @return NOXTLS_RETURN_BAD_DATA for a corrupt key or a detected state
 *         rollback, NOXTLS_RETURN_NOT_ENOUGH_MEMORY for a short workspace.
 */
noxtls_return_t noxtls_hss_key_load(noxtls_hss_key_t *key,
                                    const uint8_t *private_key, uint32_t private_key_len,
                                    uint8_t *workspace, uint32_t workspace_len,
                                    uint32_t subtree_height, uint32_t flags,
                                    noxtls_hss_persist_fn persist, void *persist_user);
/**
 * @brief Sign a message with the next one-time key (persisting state first).
 * @param[out] signature Buffer of signature_cap >= noxtls_hss_signature_len() bytes.
 * @param[out] signature_len Set to the signature length on success, 0 otherwise.
 * @return NOXTLS_RETURN_KEY_EXHAUSTED when no signatures are left; the
 *         persistence callback's error code if persisting failed (nothing is
 *         signed); NOXTLS_RETURN_FAILED if the self-check failed (the index
 *         is burned and the workspace rebuilt on the next call).
 */
noxtls_return_t noxtls_hss_sign(noxtls_hss_key_t *key,
                                const uint8_t *message, uint32_t message_len,
                                uint8_t *signature, uint32_t signature_cap,
                                uint32_t *signature_len);
/** @brief Persist a reservation of count more indices now (count >= 1). */
noxtls_return_t noxtls_hss_key_reserve(noxtls_hss_key_t *key, uint32_t count);
/** @brief Number of indices noxtls_hss_sign() reserves per persist (default 1). */
noxtls_return_t noxtls_hss_key_set_reserve(noxtls_hss_key_t *key, uint32_t count);
/** @return Signatures left (0 if exhausted or key invalid). */
uint64_t noxtls_hss_key_remaining(const noxtls_hss_key_t *key);
/** @brief Write the public key of a loaded key. */
noxtls_return_t noxtls_hss_key_public_key(const noxtls_hss_key_t *key, uint8_t *public_key,
                                          uint32_t public_key_cap, uint32_t *public_key_len);
/** @brief Wipe a working key and free a library-allocated workspace. */
void noxtls_hss_key_free(noxtls_hss_key_t *key);

/* ---- legacy preset API ---------------------------------------------------- */

/** @brief Map a preset to its parameter set. */
noxtls_return_t noxtls_hss_params_from_preset(noxtls_lms_param_t param, noxtls_hss_params_t *params);

uint32_t noxtls_lms_public_key_len(noxtls_lms_param_t param);
/** @return NOXTLS_HSS_PRIVATE_KEY_LEN for a valid preset. */
uint32_t noxtls_lms_secret_key_len(noxtls_lms_param_t param);
uint32_t noxtls_lms_signature_len(noxtls_lms_param_t param);

/** @brief Random key pair for a preset (noxtls_hss_keygen with DRBG seed and I). */
noxtls_return_t noxtls_lms_keygen(noxtls_lms_param_t param,
                                  uint8_t *public_key,
                                  uint32_t public_key_len,
                                  uint8_t *secret_key,
                                  uint32_t secret_key_len);

/**
 * @brief Stateless signing entry point: always fails closed.
 *
 * A const secret key cannot record that a one-time key was used, so signing
 * through this prototype would reuse LM-OTS keys.  It returns
 * NOXTLS_RETURN_NOT_SUPPORTED; use noxtls_hss_key_load() + noxtls_hss_sign().
 */
noxtls_return_t noxtls_lms_sign(noxtls_lms_param_t param,
                                const uint8_t *secret_key,
                                const uint8_t *message,
                                uint32_t message_len,
                                uint8_t *signature,
                                uint32_t *signature_len);

/**
 * @brief Verify against a preset: the public key must be
 *        noxtls_lms_public_key_len(param) bytes and every level of the key and
 *        signature must use the preset's typecodes.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if
 *         verification fails.
 */
noxtls_return_t noxtls_lms_verify(noxtls_lms_param_t param,
                                  const uint8_t *public_key,
                                  const uint8_t *message,
                                  uint32_t message_len,
                                  const uint8_t *signature,
                                  uint32_t signature_len);

#endif /* NOXTLS_FEATURE_LMS_HSS */

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_LMS_H_ */
