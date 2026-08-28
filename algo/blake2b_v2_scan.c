/*
 * scanhash_blake2b_v2 - BIP-110 V2 header mining loop
 *
 * Three-level nonce scan: nNonce (L1/ASIC) + m_nonce2 (L2) + m_nonce3 (L4)
 * Uses the three-stage BLAKE2b-256 hash from crypto/blake2b_v2.c
 *
 * Performance: h1, h2, hash1 (coinb1) and prevblock_hidden are all
 * nonce-independent and computed ONCE per job. The hot loop only runs the
 * ASIC-profile BLAKE2b-256 over the nonce-varying input.
 */

#include "miner.h"
#include <string.h>
#include <stdint.h>

#define V2_NONCE3_STEP  1        // L4 nonce increment
#define V2_NONCE3_MAX   0x100u   // 8-bit space (256 values)

// Compare hash against target (both in LE uint32 arrays, 8 words = 256 bits)
static int v2_fulltest(const uint8_t *hash, const uint32_t *ptarget)
{
    uint32_t hash_le[8];
    for (int i = 0; i < 8; i++)
        memcpy(&hash_le[i], hash + i * 4, 4);

    for (int i = 7; i >= 0; i--) {
        if (hash_le[i] < ptarget[i])
            return 1;
        if (hash_le[i] > ptarget[i])
            return 0;
    }
    return 1; // equal
}

int scanhash_blake2b_v2(int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done)
{
    struct block_header_v2 *hdr = &work->v2_hdr;
    uint32_t *ptarget = work->target;
    uint32_t start_nonce = hdr->nNonce;
    uint64_t total_hashes = 0;

    // Precompute all nonce-independent values once per job.
    uint8_t h1_hash[32], h2_hash[32], hash1[32], prevblock_hidden[32];
    bip110_compute_h1(hdr, h1_hash);
    bip110_compute_h2(h1_hash, hdr->m_mm_rhs, h2_hash);
    bip110_compute_hash1(h2_hash, hdr->m_extranonce, hash1);
    bip110_compute_prevblock_hidden(hdr->hashPrevBlock, prevblock_hidden);

    // Scan: nonce3 outer, nonce2 middle, nonce1 inner
    for (uint32_t n3 = hdr->m_nonce3; n3 < V2_NONCE3_MAX; n3 += V2_NONCE3_STEP) {
        if (work_restart[thr_id].restart)
            break;

        for (uint32_t n2 = hdr->m_nonce2; n2 != 0xFFFFFFFFu; n2++) {
            if (work_restart[thr_id].restart)
                break;

            hdr->m_nonce3 = n3;
            hdr->m_nonce2 = n2;

            // Inner loop: L1/ASIC nonce
            uint32_t n1 = hdr->nNonce;
            while (n1 < max_nonce) {
                hdr->nNonce = n1;

                uint8_t pow_hash[32];
                bip110_compute_pow_hash_pre(hdr, h2_hash, hash1,
                                            prevblock_hidden, pow_hash);

                total_hashes++;

                if (v2_fulltest(pow_hash, ptarget)) {
                    *hashes_done = total_hashes;
                    return 1;
                }

                n1++;
                if (work_restart[thr_id].restart)
                    break;
            }
            hdr->nNonce = start_nonce; // reset for next n2
        }
    }

    *hashes_done = total_hashes;
    return 0;
}
