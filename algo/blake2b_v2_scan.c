/*
 * scanhash_blake2b_v2 - BIP-110 V2 header mining loop (DATUM gateway)
 *
 * Uses the three-stage BLAKE2b-256 hash from crypto/blake2b_v2.c, fixed to
 * ASIC profile 1 (no merge-mining, null XOR key) - see stratum_gen_work()
 * in cpu-miner.c for how the job is built. h2 and hash1 are nonce-
 * independent and precomputed once per job there; this loop only varies
 * nNonce (m_nonce2/m_nonce3/m_time_offset are fixed at 0).
 */

#include "miner.h"
#include <string.h>
#include <stdint.h>

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
    uint32_t n = hdr->nNonce;
    uint64_t total_hashes = 0;

    do {
        hdr->nNonce = n;

        uint8_t pow_hash_display[32], pow_hash[32];
        /* prevblock_hidden is unused by ASIC profile 1 (see
         * crypto/blake2b_v2.c) - pass a zero buffer. */
        static const uint8_t zero32[32] = {0};
        bip110_compute_pow_hash_pre(hdr, work->blake2b_h2, work->blake2b_hash1,
                                    zero32, pow_hash_display);
        /* bip110_compute_pow_hash_pre() returns "display order" (matching
         * the JSON test-vector convention); compare_hashes()/v2_fulltest()
         * expect "internal order" (byte[31] = MSB) - reverse before compare,
         * same convention the gateway side uses. */
        for (int i = 0; i < 32; i++)
            pow_hash[31 - i] = pow_hash_display[i];

        total_hashes++;

        if (v2_fulltest(pow_hash, ptarget)) {
            work_set_target_ratio(work, (uint32_t*)pow_hash);
            *hashes_done = total_hashes;
            work->data[19] = n;
            hdr->nNonce = n;
            return 1;
        }

        n++;
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = total_hashes;
    work->data[19] = n;
    hdr->nNonce = n;
    return 0;
}
