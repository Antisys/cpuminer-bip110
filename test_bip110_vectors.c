/*
 * BIP-110 V2 Test Vector Verification
 * Self-contained — only uses crypto/blake2b.c + crypto/blake2b_v2.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "crypto/blake2b.h"

// Forward declarations from blake2b_v2.c
struct block_header_v2;
extern void bip110_tagged_hash(const char *tag, const uint8_t *data, size_t len, uint8_t *out);
extern void bip110_compute_h1_raw(uint32_t version, const uint8_t *prevblock,
                                   uint32_t height, const uint8_t *merkle_root,
                                   uint32_t time_on_wire, uint32_t nBits,
                                   uint16_t txcount, uint8_t flags,
                                   uint8_t clear_bits, const uint8_t *xor_key,
                                   uint8_t *h1_hash);
extern void bip110_compute_h2(const uint8_t *h1_hash, const uint8_t *mm_rhs, uint8_t *h2_hash);
extern void bip110_compute_pow_hash_raw(uint32_t nNonce, uint32_t nonce2, uint32_t nonce3,
                                         uint32_t time_on_wire, const uint8_t *extranonce,
                                         const uint8_t *h2_hash, uint8_t flags,
                                         uint8_t clear_bits, const uint8_t *xor_key,
                                         const uint8_t *prevblock, uint32_t m_time_offset,
                                         uint8_t *final_hash);

static bool hex2bin_local(unsigned char *p, const char *hexstr, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hexstr + 2*i, "%2x", &byte) != 1) return false;
        p[i] = (unsigned char)byte;
    }
    return true;
}
#define hex2bin hex2bin_local

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static int check(const char *stage, const uint8_t *got, const char *expected_hex, size_t len)
{
    uint8_t expected[64];
    hex2bin(expected, expected_hex, len);
    if (memcmp(got, expected, len) == 0) {
        printf("  %s: PASS\n", stage);
        return 0;
    } else {
        printf("  %s: FAIL\n", stage);
        printf("    Got:      "); print_hex("", got, len);
        printf("    Expected: %s\n", expected_hex);
        return 1;
    }
}

/* Test 1: TaggedHash of empty data with known tag */
static int test_tagged_hash(void)
{
    printf("=== Test: TaggedHash ===\n");
    uint8_t result[32];
    bip110_tagged_hash("test", (const uint8_t*)"", 0, result);
    return check("TaggedHash", result,
        "d294f6e585874fe640be4ce636e6ef9e3adc27620aa3221fdcf5c0a7c11c6f67", 32);
}

/*
 * VECTOR 1: profile_0_time_offset
 * From PR #359 block_header_v2.json
 */
static int test_vector_1(void)
{
    printf("=== VECTOR 1: profile_0_time_offset ===\n");
    int fails = 0;

    /* Set up header fields */
    uint32_t version = 0x20000000;
    uint8_t prevblock[32], merkle_root[32], mm_rhs[32], extranonce[16];
    /* Internal order (reversed from JSON display) — uint128/uint256 serialized internal */
    hex2bin(prevblock, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", 32);
    /* Merkle root in INTERNAL byte order (reversed from JSON display) — h1 uses as-is */
    hex2bin(merkle_root, "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0", 32);
    hex2bin(extranonce, "ffeeddccbbaa99887766554433221100", 16);
    hex2bin(mm_rhs, "8967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab", 32);

    uint32_t time_on_wire = 2000000000 - 600;  /* nTime - m_time_offset */
    uint32_t nBits = 0x1d00ffff;
    uint32_t nNonce = 0x0badf00d;
    uint32_t nonce2 = 0x11223344;
    uint32_t nonce3 = 0x89abcdef;
    uint16_t txcount = 3;
    uint8_t flags = 0x1c;
    uint8_t clear_bits = 0;
    uint8_t xor_key[16];
    memset(xor_key, 0, 16);
    uint32_t height = 840000;

    /* Stage 1: h1 */
    uint8_t h1[32];
    bip110_compute_h1_raw(version, prevblock, height, merkle_root,
                          time_on_wire, nBits, txcount, flags,
                          clear_bits, xor_key, h1);
    fails += check("h1", h1,
        "4ff7ec7f24f6935064cb962ec8cc0c947d60621cc22c5ba8516b0b995cd0c01b", 32);

    /* Stage 2: h2 */
    uint8_t h2[32];
    bip110_compute_h2(h1, mm_rhs, h2);
    fails += check("h2", h2,
        "ab5becb2336a3701557b0f6e33de39bd333072b8494c7c60952a8e8a636565e3", 32);

    /* Stage 3: pow_hash (final block hash, xor_key=0 so mask=0) */
    uint8_t pow_hash[32];
    bip110_compute_pow_hash_raw(nNonce, nonce2, nonce3, time_on_wire,
                                extranonce, h2, flags, clear_bits, xor_key,
                                prevblock, 600, pow_hash);
    fails += check("block_hash (xor_key=0, block_hash==blake2b_2)", pow_hash,
        "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704", 32);

    return fails;
}

/*
 * VECTOR 2: profile_1_time_offset_nonzero_key
 */
static int test_vector_2(void)
{
    printf("=== VECTOR 2: profile_1_nonzero_key ===\n");
    int fails = 0;

    uint32_t version = 0x20000000;
    uint8_t prevblock[32], merkle_root[32], mm_rhs[32], extranonce[16];
    uint8_t xor_key[16];
    /* Internal order (reversed from JSON display) — uint128/uint256 serialized internal */
    hex2bin(prevblock, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", 32);
    /* Merkle root in INTERNAL byte order (reversed from JSON display) — h1 uses as-is */
    hex2bin(merkle_root, "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0", 32);
    hex2bin(extranonce, "ffeeddccbbaa99887766554433221100", 16);
    hex2bin(xor_key, "efcdab8967452301efcdab8967452301", 16);
    hex2bin(mm_rhs, "8967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab", 32);

    uint32_t time_on_wire = 2000000000 - 600;  /* nTime - m_time_offset */
    uint32_t nBits = 0x1d00ffff;
    uint32_t nNonce = 0x0badf00d;
    uint32_t nonce2 = 0x11223344;
    uint32_t nonce3 = 0x89abcdef;
    uint16_t txcount = 1;
    uint8_t flags = 0x1d;  /* asic_profile=1 */
    uint8_t clear_bits = 0;
    uint32_t height = 840001;

    uint8_t h1[32], h2[32], pow_hash[32];

    bip110_compute_h1_raw(version, prevblock, height, merkle_root,
                          time_on_wire, nBits, txcount, flags,
                          clear_bits, xor_key, h1);
    fails += check("h1", h1,
        "b1fd91c55ba79811b18bb0b0d84d30c670c65243624cdddc510a74e0dd5a0123", 32);

    bip110_compute_h2(h1, mm_rhs, h2);
    fails += check("h2", h2,
        "be70c7fd6151172efb761561f3087bd61d97ccf070a1b05ae4c5d458686523d7", 32);

    bip110_compute_pow_hash_raw(nNonce, nonce2, nonce3, time_on_wire,
                                extranonce, h2, flags, clear_bits, xor_key,
                                prevblock, 600, pow_hash);
    fails += check("block_hash", pow_hash,
        "44b383821dea9af8d7d81ba7741c34ac8c07ab81ab081d8b6bf0575a787a1eef", 32);

    return fails;
}

/*
 * VECTOR 5: profile_0_time_offset_disabled, xor_key_mask_clear=255
 */
static int test_vector_5(void)
{
    printf("=== VECTOR 5: time_offset_disabled, clear=255 ===\n");
    int fails = 0;

    uint32_t version = 0x20000000;
    uint8_t prevblock[32], merkle_root[32], extranonce[16];
    uint8_t xor_key[16];
    /* Internal order (reversed from JSON display) — uint128/uint256 serialized internal */
    hex2bin(prevblock, "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", 32);
    /* Merkle root in INTERNAL byte order (reversed from JSON display) — h1 uses as-is */
    hex2bin(merkle_root, "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0", 32);
    hex2bin(extranonce, "ffeeddccbbaa99887766554433221100", 16);
    hex2bin(xor_key, "22222222222222221111111111111111", 16);

    uint32_t time_on_wire = 0x77359400;  /* nTime (UseTimeOffset DISABLED, no subtraction) */
    uint32_t nBits = 0x1d00ffff;
    uint32_t nNonce = 0xffffffff;
    uint32_t nonce2 = 0x11223344;
    uint32_t nonce3 = 0x89abcdef;
    uint16_t txcount = 3;
    uint8_t flags = 0x18;  /* UseTimeOffset DISABLED */
    uint8_t clear_bits = 255;
    uint32_t height = 840000;
    uint8_t mm_rhs[32];
    memset(mm_rhs, 0, 32);

    uint8_t h1[32], h2[32], pow_hash[32];

    bip110_compute_h1_raw(version, prevblock, height, merkle_root,
                          time_on_wire, nBits, txcount, flags,
                          clear_bits, xor_key, h1);
    fails += check("h1", h1,
        "f06e36d21af2982442bff107cf6546b4440421f841a49ed027d4fa11e3e504e6", 32);

    bip110_compute_h2(h1, mm_rhs, h2);
    fails += check("h2", h2,
        "eae5d77dab38f5094ad95e848237614bd734f7fbc66f306422eccd2f009dc91e", 32);

    /* xor_key != 0, mask gets computed, but clear_bits=255 zeros everything -> mask=0x01 at byte 31 */
    bip110_compute_pow_hash_raw(nNonce, nonce2, nonce3, time_on_wire,
                                extranonce, h2, flags, clear_bits, xor_key,
                                prevblock, 1432778632, pow_hash);
    fails += check("block_hash", pow_hash,
        "c31b24420d67f86e524f980a24a18e88f36c821046d5288251b5d88998c69f86", 32);

    return fails;
}

int main(void)
{
    printf("BIP-110 V2 Test Vector Verification\n");
    printf("====================================\n\n");

    int total_fails = 0;

    total_fails += test_tagged_hash();
    total_fails += test_vector_1();
    total_fails += test_vector_2();
    total_fails += test_vector_5();

    printf("\n====================================\n");
    if (total_fails == 0)
        printf("All checks PASSED\n");
    else
        printf("%d check(s) FAILED\n", total_fails);

    return total_fails;
}
