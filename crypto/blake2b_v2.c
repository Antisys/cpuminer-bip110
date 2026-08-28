/*
 * BIP-110 / BLAKE2b Block Header V2 - Three-stage hash computation
 *
 * Based on Bitcoin Knots PR #359 by luke-jr (pow_hf_blake2b branch).
 * Implements the three-stage BLAKE2b-256 block hash for V2 headers.
 *
 * TaggedHash uses SHA256 (BIP-340 style), PoW uses BLAKE2b-256.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <openssl/sha.h>

#include "blake2b.h"
#include "../miner.h"

// ============================================================================
// TaggedHash (BIP-340 style): SHA256(SHA256(tag) || SHA256(tag) || data)
// ============================================================================

static void sha256_32(const uint8_t *in, uint8_t *out)
{
    SHA256(in, 32, out);
}

void tagged_hash(const char *tag, const uint8_t *data, size_t len, uint8_t *out)
{
    uint8_t tag_hash[32];
    SHA256((const uint8_t*)tag, strlen(tag), tag_hash);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tag_hash, 32);
    SHA256_Update(&ctx, tag_hash, 32);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

void bip110_tagged_hash(const char *tag, const uint8_t *data, size_t len, uint8_t *out)
{
    tagged_hash(tag, data, len, out);
}

// ============================================================================
// XOR key hash
// ============================================================================

static void compute_xor_key_hash(const uint8_t *xor_key, uint8_t *key_hash)
{
    tagged_hash("Bitcoin block hash PoW XOR key", xor_key, 16, key_hash);
}

// ============================================================================
// Stage 1: h1 = TaggedHash("Bitcoin block header 1", fields...)
// ============================================================================

void bip110_compute_h1(const struct block_header_v2 *hdr, uint8_t *h1_hash)
{
    uint32_t complete_version = BIP110_VERSION_V2_FLAG | (hdr->version & ~BIP110_VERSION_V2_FLAG);

    uint8_t xor_key_hash[32];
    compute_xor_key_hash(hdr->m_xor_key, xor_key_hash);

    uint8_t h1_input[119];
    size_t pos = 0;

    memcpy(h1_input + pos, &complete_version, 4);          pos += 4;
    /* C++: hashPrevBlock.ReversedBytes() — struct stores wire order, h1 needs display order */
    for (int i = 0; i < 32; i++)
        h1_input[pos + i] = hdr->hashPrevBlock[31 - i];
    pos += 32;
    memcpy(h1_input + pos, &hdr->m_height, 4);             pos += 4;
    memcpy(h1_input + pos, hdr->hashMerkleRoot, 32);       pos += 32;
    memcpy(h1_input + pos, &hdr->time_on_wire, 4);         pos += 4;
    h1_input[pos] = 0x00;                                   pos += 1;
    memcpy(h1_input + pos, &hdr->nBits, 4);                pos += 4;
    uint32_t txcount_32 = (uint32_t)hdr->m_txcount;
    memcpy(h1_input + pos, &txcount_32, 4);                 pos += 4;
    h1_input[pos] = hdr->m_flags;                           pos += 1;
    h1_input[pos] = hdr->m_xor_key_mask_clear_bits;        pos += 1;
    memcpy(h1_input + pos, xor_key_hash, 32);               pos += 32;

    tagged_hash("Bitcoin block header 1", h1_input, pos, h1_hash);
}

// Raw version for testing (no struct dependency beyond miner.h types)
void bip110_compute_h1_raw(uint32_t version, const uint8_t *prevblock,
                           uint32_t height, const uint8_t *merkle_root,
                           uint32_t time_on_wire, uint32_t nBits,
                           uint16_t txcount, uint8_t flags,
                           uint8_t clear_bits, const uint8_t *xor_key,
                           uint8_t *h1_hash)
{
    struct block_header_v2 hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = version;
    memcpy(hdr.hashPrevBlock, prevblock, 32);
    hdr.m_height = height;
    memcpy(hdr.hashMerkleRoot, merkle_root, 32);
    hdr.time_on_wire = time_on_wire;
    hdr.nBits = nBits;
    hdr.m_txcount = txcount;
    hdr.m_flags = flags;
    hdr.m_xor_key_mask_clear_bits = clear_bits;
    memcpy(hdr.m_xor_key, xor_key, 16);
    bip110_compute_h1(&hdr, h1_hash);
}

// ============================================================================
// Stage 2: h2 = TaggedHash("Merge-mining hook", h1_hash || 0x00*32 || mm_rhs)
// ============================================================================

void bip110_compute_h2(const uint8_t *h1_hash, const uint8_t *mm_rhs, uint8_t *h2_hash)
{
    uint8_t h2_input[96];
    memcpy(h2_input, h1_hash, 32);
    memset(h2_input + 32, 0, 32);
    memcpy(h2_input + 64, mm_rhs, 32);

    tagged_hash("Merge-mining hook", h2_input, sizeof(h2_input), h2_hash);
}

// ============================================================================
// Stage 3: ASIC-profile-dependent BLAKE2b-256 hash
//
// hash1 = BLAKE2b-256(0x00*4 || SHA256(h2) || m_extranonce)
// hash2 = BLAKE2b-256(asic_input)
// block_hash = hash2 XOR mask
// ============================================================================

void bip110_compute_hash1(const uint8_t *h2_hash, const uint8_t *extranonce,
                          uint8_t *hash1)
{
    /* C++: ss << (uint32_t)0 << h2_hash << m_extranonce — h2_hash used directly */
    uint8_t coinb1_input[52];
    memset(coinb1_input, 0, 4);
    memcpy(coinb1_input + 4, h2_hash, 32);
    memcpy(coinb1_input + 36, extranonce, 16);

    blake2b_ctx ctx;
    blake2b_init(&ctx, 32, NULL, 0);
    blake2b_update(&ctx, coinb1_input, sizeof(coinb1_input));
    blake2b_final(&ctx, hash1);
}

void bip110_compute_prevblock_hidden(const uint8_t *prevblock, uint8_t *hidden)
{
    uint8_t reversed[32];
    for (int i = 0; i < 32; i++)
        reversed[i] = prevblock[31 - i];

    tagged_hash("Bitcoin prevblock header, hashed", reversed, 32, hidden);
    memset(hidden, 0, 6);
}

/*
 * Compute the ASIC-profile-dependent BLAKE2b-256 hash.
 * hash1 (coinb1) and prevblock_hidden are nonce-independent and should be
 * precomputed once via bip110_compute_hash1 / bip110_compute_prevblock_hidden.
 */
void bip110_compute_pow_hash_pre(const struct block_header_v2 *hdr,
                                 const uint8_t *h2_hash,
                                 const uint8_t *hash1,
                                 const uint8_t *prevblock_hidden,
                                 uint8_t *final_hash)
{
    uint8_t asic_input[160];
    size_t input_len = 0;

    uint8_t blake2b_2[32];

    switch (hdr->m_flags & BIP110_FLAG_ASIC_PROFILE_MASK) {
    case BIP110_ASIC_PROFILE_0:
        memcpy(asic_input + input_len, prevblock_hidden, 32);   input_len += 32;
        memcpy(asic_input + input_len, &hdr->nNonce, 4);        input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce2, 4);      input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_time_offset, 4); input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce3, 4);      input_len += 4;
        memcpy(asic_input + input_len, hash1, 32);               input_len += 32;
        break;

    case BIP110_ASIC_PROFILE_1:
        memcpy(asic_input + input_len, &hdr->nNonce, 4);        input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce2, 4);      input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce3, 4);      input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_time_offset, 4); input_len += 4;
        memcpy(asic_input + input_len, hash1, 32);               input_len += 32;
        memcpy(asic_input + input_len, h2_hash, 32);             input_len += 32;
        break;

    case BIP110_ASIC_PROFILE_2:
        memset(asic_input + input_len, 0, 48);                   input_len += 48;
        memcpy(asic_input + input_len, h2_hash, 32);             input_len += 32;
        memcpy(asic_input + input_len, &hdr->nNonce, 4);        input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce2, 4);      input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_time_offset, 4); input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce3, 4);      input_len += 4;
        memcpy(asic_input + input_len, hash1, 32);               input_len += 32;
        break;

    case BIP110_ASIC_PROFILE_3:
        memset(asic_input + input_len, 0, 80);                   input_len += 80;
        memcpy(asic_input + input_len, h2_hash, 32);             input_len += 32;
        memcpy(asic_input + input_len, &hdr->nNonce, 4);        input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce2, 4);      input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_time_offset, 4); input_len += 4;
        memcpy(asic_input + input_len, &hdr->m_nonce3, 4);      input_len += 4;
        memcpy(asic_input + input_len, hash1, 32);               input_len += 32;
        break;
    }

    blake2b_ctx ctx;
    blake2b_init(&ctx, 32, NULL, 0);
    blake2b_update(&ctx, asic_input, input_len);
    blake2b_final(&ctx, blake2b_2);

    uint8_t zero_key[16] = {0};
    if (memcmp(hdr->m_xor_key, zero_key, 16) != 0)
        bip110_apply_xor_mask(blake2b_2, hdr->m_xor_key,
                               hdr->m_xor_key_mask_clear_bits, final_hash);
    else
        memcpy(final_hash, blake2b_2, 32);
}

void bip110_compute_pow_hash(const struct block_header_v2 *hdr,
                              const uint8_t *h2_hash,
                              uint8_t *final_hash)
{
    uint8_t hash1[32];
    bip110_compute_hash1(h2_hash, hdr->m_extranonce, hash1);

    uint8_t prevblock_hidden[32];
    bip110_compute_prevblock_hidden(hdr->hashPrevBlock, prevblock_hidden);

    bip110_compute_pow_hash_pre(hdr, h2_hash, hash1, prevblock_hidden, final_hash);
}

// Raw version for testing
void bip110_compute_pow_hash_raw(uint32_t nNonce, uint32_t nonce2, uint32_t nonce3,
                                 uint32_t time_on_wire, const uint8_t *extranonce,
                                 const uint8_t *h2_hash, uint8_t flags,
                                 uint8_t clear_bits, const uint8_t *xor_key,
                                 const uint8_t *prevblock, uint32_t m_time_offset,
                                 uint8_t *final_hash)
{
    struct block_header_v2 hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.nNonce = nNonce;
    hdr.m_nonce2 = nonce2;
    hdr.m_nonce3 = nonce3;
    hdr.time_on_wire = time_on_wire;
    hdr.m_time_offset = m_time_offset;
    memcpy(hdr.m_extranonce, extranonce, 16);
    hdr.m_flags = flags;
    hdr.m_xor_key_mask_clear_bits = clear_bits;
    memcpy(hdr.m_xor_key, xor_key, 16);
    memcpy(hdr.hashPrevBlock, prevblock, 32);
    bip110_compute_pow_hash(&hdr, h2_hash, final_hash);
}

// ============================================================================
// XOR Mask
// ============================================================================

void bip110_apply_xor_mask(const uint8_t *hash2, const uint8_t *xor_key,
                            uint8_t clear_bits, uint8_t *final_hash)
{
    uint8_t mask[32];
    tagged_hash("Bitcoin block hash PoW XOR mask", xor_key, 16, mask);

    size_t clear_bytes = clear_bits / 8;
    if (clear_bytes > 0)
        memset(mask, 0, clear_bytes < 32 ? clear_bytes : 32);

    uint8_t remaining_bits = clear_bits % 8;
    if (remaining_bits > 0 && clear_bytes < 32)
        mask[clear_bytes] &= 0xFF >> remaining_bits;

    for (int i = 0; i < 32; i++)
        final_hash[i] = hash2[i] ^ mask[i];
}

// ============================================================================
// Create V2 Header
// ============================================================================

int bip110_create_header(const uint8_t *prevhash, const uint8_t *merkle_root,
                          uint32_t time, uint32_t nbits, uint32_t height,
                          uint32_t txcount, struct block_header_v2 *hdr)
{
    memset(hdr, 0, sizeof(struct block_header_v2));
    hdr->version = BIP110_VERSION_V2_FLAG;
    memcpy(hdr->hashPrevBlock, prevhash, 32);
    memcpy(hdr->hashMerkleRoot, merkle_root, 32);
    hdr->time_on_wire = time;
    hdr->nBits = nbits;
    hdr->m_txcount = (uint16_t)(txcount > 0xFFFF ? 0xFFFF : txcount);
    hdr->m_flags = BIP110_FLAG_USE_TIME_OFFSET;
    hdr->m_height = height;
    return 0;
}
