/*
 * V2 BLAKE2b hash-rate benchmark — measures bip110_compute_pow_hash_pre
 * directly (the hot path), avoiding the scan loop's nested nonce structure.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "miner.h"

static void h2b(unsigned char *p, const char *hexstr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hexstr + 2*i, "%2x", &byte);
        p[i] = (unsigned char)byte;
    }
}
#define hex2bin h2b

int main(void)
{
    struct block_header_v2 hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.version = BIP110_VERSION_V2_FLAG | 0x20000000;
    hex2bin(hdr.hashPrevBlock, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", 32);
    hex2bin(hdr.hashMerkleRoot, "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0", 32);
    hdr.time_on_wire = 2000000000 - 600;
    hdr.nBits = 0x1d00ffff;
    hdr.nNonce = 0;
    hdr.m_nonce2 = 0;
    hdr.m_nonce3 = 0;
    hex2bin(hdr.m_extranonce, "ffeeddccbbaa99887766554433221100", 16);
    hdr.m_time_offset = 600;
    hdr.m_txcount = 3;
    hdr.m_flags = BIP110_ASIC_PROFILE_0 | BIP110_FLAG_USE_TIME_OFFSET;
    hdr.m_xor_key_mask_clear_bits = 0;
    memset(hdr.m_xor_key, 0, 16);
    hdr.m_height = 840000;
    hex2bin(hdr.m_mm_rhs, "8967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab", 32);

    uint8_t h1[32], h2[32], hash1[32], prevblock_hidden[32];
    bip110_compute_h1(&hdr, h1);
    bip110_compute_h2(h1, hdr.m_mm_rhs, h2);
    bip110_compute_hash1(h2, hdr.m_extranonce, hash1);
    bip110_compute_prevblock_hidden(hdr.hashPrevBlock, prevblock_hidden);

    const uint64_t N = 10000000;  /* 10M hashes */
    uint8_t out[32];
    volatile uint8_t sink = 0;

    /* warmup */
    for (int i = 0; i < 100000; i++)
        bip110_compute_pow_hash_pre(&hdr, h2, hash1, prevblock_hidden, out);

    struct timespec t0, t1;

    /* Optimized path: hash1 + prevblock_hidden precomputed once */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < N; i++) {
        hdr.nNonce = (uint32_t) i;
        bip110_compute_pow_hash_pre(&hdr, h2, hash1, prevblock_hidden, out);
        sink ^= out[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("OPTIMIZED (%llu hashes, %.3fs): %.1f kH/s  (%.2f us/hash)\n",
           (unsigned long long) N, secs, (N / secs) / 1000.0, (secs / N) * 1e6);

    /* Original path: hash1 + prevblock_hidden recomputed per hash */
    const uint64_t N2 = 1000000;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < N2; i++) {
        hdr.nNonce = (uint32_t) i;
        bip110_compute_pow_hash(&hdr, h2, out);
        sink ^= out[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("ORIGINAL (%llu hashes, %.3fs): %.1f kH/s  (%.2f us/hash)\n",
           (unsigned long long) N2, secs, (N2 / secs) / 1000.0, (secs / N2) * 1e6);

    printf("sink=%02x\n", (unsigned) sink);
    return 0;
}
