/*
 * V2 BLAKE2b multi-thread benchmark — measures bip110_compute_pow_hash_pre
 * across N threads, each on its own nonce range (simulating the miner).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "miner.h"

static void h2b(unsigned char *p, const char *hexstr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hexstr + 2*i, "%2x", &byte);
        p[i] = (unsigned char)byte;
    }
}
#define hex2bin h2b

struct thread_arg {
    int id;
    struct block_header_v2 hdr;
    uint8_t h2[32], hash1[32], prevblock_hidden[32];
    uint64_t hashes;
    uint64_t ns;
};

static void *worker(void *argp)
{
    struct thread_arg *a = (struct thread_arg *) argp;
    struct block_header_v2 hdr = a->hdr;
    uint8_t out[32];
    volatile uint8_t sink = 0;

    uint64_t start = (uint64_t) a->id * (UINT32_MAX / 8);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < a->hashes; i++) {
        hdr.nNonce = (uint32_t)(start + i);
        bip110_compute_pow_hash_pre(&hdr, a->h2, a->hash1, a->prevblock_hidden, out);
        sink ^= out[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    a->ns = (t1.tv_sec - t0.tv_sec) * 1000000000UL + (t1.tv_nsec - t0.tv_nsec);
    (void)sink;
    return NULL;
}

int main(int argc, char **argv)
{
    int nthreads = argc > 1 ? atoi(argv[1]) : 8;
    uint64_t hashes_per_thread = argc > 2 ? strtoull(argv[2], NULL, 10) : 3000000;
    if (nthreads > 8) nthreads = 8;

    struct block_header_v2 base;
    memset(&base, 0, sizeof(base));
    base.version = BIP110_VERSION_V2_FLAG | 0x20000000;
    hex2bin(base.hashPrevBlock, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", 32);
    hex2bin(base.hashMerkleRoot, "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0", 32);
    base.time_on_wire = 2000000000 - 600;
    base.nBits = 0x1d00ffff;
    base.m_time_offset = 600;
    base.m_txcount = 3;
    base.m_flags = BIP110_ASIC_PROFILE_0 | BIP110_FLAG_USE_TIME_OFFSET;
    memset(base.m_xor_key, 0, 16);
    base.m_height = 840000;
    hex2bin(base.m_mm_rhs, "8967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab", 32);
    hex2bin(base.m_extranonce, "ffeeddccbbaa99887766554433221100", 16);

    uint8_t h1[32];
    bip110_compute_h1(&base, h1);

    pthread_t threads[8];
    struct thread_arg args[8];
    for (int i = 0; i < nthreads; i++) {
        args[i].id = i;
        args[i].hdr = base;
        bip110_compute_h2(h1, base.m_mm_rhs, args[i].h2);
        bip110_compute_hash1(args[i].h2, base.m_extranonce, args[i].hash1);
        bip110_compute_prevblock_hidden(base.hashPrevBlock, args[i].prevblock_hidden);
        args[i].hashes = hashes_per_thread;
        args[i].ns = 0;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }

    uint64_t total_hashes = 0;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
        total_hashes += args[i].hashes;
    }

    uint64_t max_ns = 0;
    for (int i = 0; i < nthreads; i++)
        if (args[i].ns > max_ns) max_ns = args[i].ns;

    double secs = max_ns / 1e9;
    printf("%d threads, %llu total hashes, wall=%.3fs\n",
           nthreads, (unsigned long long) total_hashes, secs);
    printf("V2 aggregate hash rate: %.1f kH/s\n", (total_hashes / secs) / 1000.0);
    return 0;
}
