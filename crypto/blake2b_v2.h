#ifndef BLAKE2B_V2_H
#define BLAKE2B_V2_H

#include <stdint.h>
#include <stddef.h>
#include "../miner.h"

void tagged_hash(const char *tag, const uint8_t *data, size_t len, uint8_t *out);

void bip110_tagged_hash(const char *tag, const uint8_t *data, size_t len, uint8_t *out);

void bip110_compute_h1(const struct block_header_v2 *hdr, uint8_t *h1_hash);

void bip110_compute_h1_raw(uint32_t version, const uint8_t *prevblock,
                           uint32_t height, const uint8_t *merkle_root,
                           uint32_t time_on_wire, uint32_t nBits,
                           uint16_t txcount, uint8_t flags,
                           uint8_t clear_bits, const uint8_t *xor_key,
                           uint8_t *h1_hash);

void bip110_compute_h2(const uint8_t *h1_hash, const uint8_t *mm_rhs, uint8_t *h2_hash);

void bip110_compute_pow_hash(const struct block_header_v2 *hdr,
                             const uint8_t *h2_hash, uint8_t *final_hash);

void bip110_compute_hash1(const uint8_t *h2_hash, const uint8_t *extranonce,
                          uint8_t *hash1);

void bip110_compute_prevblock_hidden(const uint8_t *prevblock, uint8_t *hidden);

void bip110_compute_pow_hash_pre(const struct block_header_v2 *hdr,
                                 const uint8_t *h2_hash,
                                 const uint8_t *hash1,
                                 const uint8_t *prevblock_hidden,
                                 uint8_t *final_hash);

void bip110_compute_pow_hash_raw(uint32_t nNonce, uint32_t nonce2, uint32_t nonce3,
                                 uint32_t time_on_wire, const uint8_t *extranonce,
                                 const uint8_t *h2_hash, uint8_t flags,
                                 uint8_t clear_bits, const uint8_t *xor_key,
                                 const uint8_t *prevblock, uint32_t m_time_offset,
                                 uint8_t *final_hash);

void bip110_apply_xor_mask(const uint8_t *hash2, const uint8_t *xor_key,
                           uint8_t clear_bits, uint8_t *final_hash);

int bip110_create_header(const uint8_t *prevhash, const uint8_t *merkle_root,
                         uint32_t time, uint32_t nbits, uint32_t height,
                         uint32_t txcount, struct block_header_v2 *hdr);

#endif
