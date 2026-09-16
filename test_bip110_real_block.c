/*
 * BIP-110 V2 real-chain validation
 *
 * The official Knots test vectors (see test_bip110_vectors.c) prove the
 * algorithm matches spec in isolation. This test goes one step further:
 * it feeds the exact raw 164-byte V2 header of a real, already-accepted
 * block from the live BIP-110 chain (pulled via `getblockheader <hash>
 * false` on a synced node) straight into the deployed
 * bip110_compute_h1/h2/pow_hash() functions, and checks the result is
 * byte-for-byte the block hash the network already agreed is valid.
 *
 * Unlike the RPC's JSON field output, the raw serialized header is in
 * plain wire/struct order for every field - no extra byte-reversal is
 * needed for extranonce/nonce2/nonce3/xor_key/mm_rhs here (that JSON
 * convention differs from both the raw wire format and the official
 * test vector fixture's JSON convention - three different conventions
 * for the same bytes, easy to mix up, which is why this test parses the
 * raw header directly instead of going through RPC JSON fields).
 *
 * Build:
 *   gcc -DHAVE_CONFIG_H -I. -o test_bip110_real_block \
 *       test_bip110_real_block.c crypto/blake2b_v2.c crypto/blake2b.c \
 *       -lssl -lcrypto
 * Run:
 *   ./test_bip110_real_block
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "miner.h"

static void hex2bin_local(uint8_t *out, const char *hex, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

int main(void)
{
    printf("BIP-110 V2 Real-Chain Block Validation\n");
    printf("=======================================\n\n");

    /* Raw serialized 164-byte V2 header of block 972452 (hash
     * 000000000000000032a57ec06aeecd0da7d4af016ee15eeb58374c40e231480d),
     * the tip of our node's synced BIP-110 chain at the time this test
     * was written. Pulled via:
     *   bitcoin-cli getblockheader <hash> false
     */
    const char *raw_hex =
        "000000a037e60dc206874dd4d51a4e3b6d46a120d39f58e25ab5114c0000000000000000ddede9325633ea2d71b4c89da2bbc2ac16da07079fbec74edb3c0e16d9a9f035d6ceaa6ac041011974188ffbe144d44ed6ceaa6a000000003253a26a030000000000000000000000c401000000000000000000000000000000000000a4d60e000000000000000000000000000000000000000000000000000000000000000000";

    const char *expected_hash =
        "000000000000000032a57ec06aeecd0da7d4af016ee15eeb58374c40e231480d";

    uint8_t raw[164];
    hex2bin_local(raw, raw_hex, 164);

    struct block_header_v2 hdr;
    memset(&hdr, 0, sizeof(hdr));
    size_t off = 0;
    memcpy(&hdr.version, raw + off, 4); off += 4;
    memcpy(hdr.hashPrevBlock, raw + off, 32); off += 32;
    memcpy(hdr.hashMerkleRoot, raw + off, 32); off += 32;
    memcpy(&hdr.time_on_wire, raw + off, 4); off += 4;
    memcpy(&hdr.nBits, raw + off, 4); off += 4;
    memcpy(&hdr.nNonce, raw + off, 4); off += 4;
    memcpy(&hdr.m_nonce2, raw + off, 4); off += 4;
    memcpy(&hdr.m_nonce3, raw + off, 4); off += 4;
    memcpy(hdr.m_extranonce, raw + off, 16); off += 16;
    memcpy(&hdr.m_time_offset, raw + off, 4); off += 4;
    memcpy(&hdr.m_txcount, raw + off, 2); off += 2;
    memcpy(&hdr.m_flags, raw + off, 1); off += 1;
    memcpy(&hdr.m_xor_key_mask_clear_bits, raw + off, 1); off += 1;
    memcpy(hdr.m_xor_key, raw + off, 16); off += 16;
    memcpy(&hdr.m_height, raw + off, 4); off += 4;
    memcpy(hdr.m_mm_rhs, raw + off, 32); off += 32;

    if (off != 164) {
        printf("FAIL: header parse consumed %zu bytes, expected 164\n", off);
        return 1;
    }

    uint8_t h1[32], h2[32], final_hash[32];
    bip110_compute_h1(&hdr, h1);
    bip110_compute_h2(h1, hdr.m_mm_rhs, h2);
    bip110_compute_pow_hash(&hdr, h2, final_hash);

    char got[65];
    for (int i = 0; i < 32; i++)
        sprintf(got + i * 2, "%02x", final_hash[i]);
    got[64] = 0;

    printf("height:   972452 (ASIC profile %d, m_flags=0x%02x)\n",
           hdr.m_flags & BIP110_FLAG_ASIC_PROFILE_MASK, hdr.m_flags);
    printf("computed: %s\n", got);
    printf("expected: %s\n", expected_hash);

    int ok = strcmp(got, expected_hash) == 0;
    printf("\n%s\n", ok ? "PASS - reproduces the real, network-accepted block hash exactly"
                         : "FAIL - does not match the real block hash");

    return ok ? 0 : 1;
}
