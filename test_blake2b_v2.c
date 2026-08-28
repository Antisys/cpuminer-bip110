/*
 * Test for BIP-110 BLAKE2b V2 header hash functions
 *
 * Tests the three-stage hash computation against known properties.
 * When the full test vectors from PR #359 are available, they can be added.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../miner.h"

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static int test_tagged_hash(void)
{
    printf("=== Test: TaggedHash ===\n");

    // Simple test: TaggedHash of empty data with known tag
    uint8_t out[32];
    tagged_hash("test", (uint8_t *)"", 0, out);
    print_hex("TaggedHash(\"test\", \"\")", out, 32);

    // Verify it's deterministic
    uint8_t out2[32];
    tagged_hash("test", (uint8_t *)"", 0, out2);
    assert(memcmp(out, out2, 32) == 0);
    printf("Deterministic: PASS\n\n");
    return 0;
}

static int test_v2_header_creation(void)
{
    printf("=== Test: V2 Header Creation ===\n");

    struct block_header_v2 hdr;

    // Create a test header
    uint8_t prevhash[32] = {0};
    uint8_t merkle[32] = {0};
    prevhash[0] = 0x01;  // some non-zero value
    merkle[0] = 0x02;

    bip110_create_header(prevhash, merkle, 1234567890, 0x1d00ffff, 840000, 100, &hdr);

    // Verify V2 flag is set
    assert(hdr.version & BIP110_VERSION_V2_FLAG);
    printf("V2 flag set: PASS\n");

    // Verify version value
    assert(hdr.version == BIP110_VERSION_V2_FLAG);
    printf("Version = 0x%08x: PASS\n", hdr.version);

    // Verify header size
    assert(sizeof(struct block_header_v2) == BIP110_HEADER_V2_SIZE);
    printf("Header size = %zu (expected %d): PASS\n",
           sizeof(struct block_header_v2), BIP110_HEADER_V2_SIZE);

    // Verify fields
    assert(hdr.hashPrevBlock[0] == 0x01);
    assert(hdr.hashMerkleRoot[0] == 0x02);
    assert(hdr.time_on_wire == 1234567890);
    assert(hdr.nBits == 0x1d00ffff);
    assert(hdr.nNonce == 0);
    assert(hdr.m_nonce2 == 0);
    assert(hdr.m_nonce3 == 0);
    assert(hdr.m_height == 840000);
    assert(hdr.m_txcount == 100);
    printf("All fields correct: PASS\n\n");
    return 0;
}

static int test_v2_header_serialization(void)
{
    printf("=== Test: V2 Header Serialization ===\n");

    struct block_header_v2 hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = BIP110_VERSION_V2_FLAG | 0x20000000;
    hdr.nBits = 0x1d00ffff;
    hdr.nNonce = 0xdeadbeef;
    hdr.m_nonce2 = 0x12345678;
    hdr.m_nonce3 = 0x9abcdef0;
    hdr.m_height = 840000;
    hdr.m_flags = BIP110_FLAG_USE_TIME_OFFSET | BIP110_ASIC_PROFILE_0;

    // Serialize manually
    uint8_t wire[164];
    memcpy(wire, &hdr, sizeof(hdr));

    // Verify offsets
    assert(*(uint32_t *)(wire + 0) == (BIP110_VERSION_V2_FLAG | 0x20000000));
    assert(*(uint32_t *)(wire + 72) == 0x1d00ffff);
    assert(*(uint32_t *)(wire + 76) == 0xdeadbeef);
    assert(*(uint32_t *)(wire + 80) == 0x12345678);
    assert(*(uint32_t *)(wire + 84) == 0x9abcdef0);
    assert(*(uint32_t *)(wire + 128) == 840000);
    assert(wire[110] == (BIP110_FLAG_USE_TIME_OFFSET | BIP110_ASIC_PROFILE_0));

    printf("Serialization offsets: PASS\n");

    // Verify total size
    assert(sizeof(wire) == 164);
    printf("Wire size = 164: PASS\n\n");
    return 0;
}

static int test_v2_hash_computation(void)
{
    printf("=== Test: V2 Hash Computation ===\n");

    struct block_header_v2 hdr;
    bip110_create_header(
        (uint8_t [32]){0}, (uint8_t [32]){0},
        1234567890, 0x1d00ffff, 840000, 100, &hdr
    );

    // Compute h1
    uint8_t h1_hash[32];
    bip110_compute_h1(&hdr, h1_hash);
    print_hex("h1_hash", h1_hash, 32);

    // Verify h1 is non-zero
    uint8_t zero[32] = {0};
    assert(memcmp(h1_hash, zero, 32) != 0);
    printf("h1 non-zero: PASS\n");

    // Compute h2
    uint8_t h2_hash[32];
    bip110_compute_h2(h1_hash, hdr.m_mm_rhs, h2_hash);
    print_hex("h2_hash", h2_hash, 32);

    assert(memcmp(h2_hash, zero, 32) != 0);
    printf("h2 non-zero: PASS\n");

    // Compute full PoW hash (profile 0, no XOR key)
    uint8_t pow_hash[32];
    bip110_compute_pow_hash(&hdr, h2_hash, pow_hash);
    print_hex("pow_hash", pow_hash, 32);

    assert(memcmp(pow_hash, zero, 32) != 0);
    printf("pow_hash non-zero: PASS\n");

    // Verify determinism
    uint8_t pow_hash2[32];
    bip110_compute_pow_hash(&hdr, h2_hash, pow_hash2);
    assert(memcmp(pow_hash, pow_hash2, 32) == 0);
    printf("Deterministic: PASS\n\n");
    return 0;
}

static int test_v2_with_xor_key(void)
{
    printf("=== Test: V2 Hash with XOR Key ===\n");

    struct block_header_v2 hdr;
    bip110_create_header(
        (uint8_t [32]){0}, (uint8_t [32]){0},
        1234567890, 0x1d00ffff, 840000, 100, &hdr
    );

    // Set a non-zero XOR key
    memset(hdr.m_xor_key, 0xab, 16);
    hdr.m_xor_key_mask_clear_bits = 4;

    uint8_t h1_hash[32], h2_hash[32], pow_hash[32], pow_hash_no_xor[32];

    bip110_compute_h1(&hdr, h1_hash);
    bip110_compute_h2(h1_hash, hdr.m_mm_rhs, h2_hash);

    // With XOR key
    bip110_compute_pow_hash(&hdr, h2_hash, pow_hash);
    print_hex("pow_hash (XOR)", pow_hash, 32);

    // Without XOR key (temporarily zero it)
    uint8_t saved_key[16];
    memcpy(saved_key, hdr.m_xor_key, 16);
    memset(hdr.m_xor_key, 0, 16);
    bip110_compute_pow_hash(&hdr, h2_hash, pow_hash_no_xor);
    memcpy(hdr.m_xor_key, saved_key, 16);
    print_hex("pow_hash (no XOR)", pow_hash_no_xor, 32);

    // They should be different
    assert(memcmp(pow_hash, pow_hash_no_xor, 32) != 0);
    printf("XOR key changes hash: PASS\n\n");
    return 0;
}

static int test_asic_profiles(void)
{
    printf("=== Test: Different ASIC Profiles ===\n");

    uint8_t h2_hash[32] = {0};  // dummy
    uint8_t hash_prev[32] = {0};

    for (int profile = 0; profile <= 3; profile++) {
        struct block_header_v2 hdr;
        bip110_create_header(hash_prev, hash_prev, 1234567890,
                              0x1d00ffff, 840000, 100, &hdr);
        hdr.m_flags = (hdr.m_flags & ~BIP110_FLAG_ASIC_PROFILE_MASK) | profile;

        uint8_t h1[32], h2[32], pow[32];
        bip110_compute_h1(&hdr, h1);
        bip110_compute_h2(h1, hdr.m_mm_rhs, h2);
        bip110_compute_pow_hash(&hdr, h2, pow);

        char label[64];
        snprintf(label, sizeof(label), "Profile %d hash", profile);
        print_hex(label, pow, 32);
    }

    // Different profiles should produce different hashes
    struct block_header_v2 hdr0, hdr1;
    bip110_create_header(hash_prev, hash_prev, 1234567890,
                          0x1d00ffff, 840000, 100, &hdr0);
    hdr1 = hdr0;
    hdr1.m_flags = (hdr1.m_flags & ~BIP110_FLAG_ASIC_PROFILE_MASK) | 1;

    uint8_t h1_0[32], h2_0[32], pow0[32];
    uint8_t h1_1[32], h2_1[32], pow1[32];

    bip110_compute_h1(&hdr0, h1_0);
    bip110_compute_h2(h1_0, hdr0.m_mm_rhs, h2_0);
    bip110_compute_pow_hash(&hdr0, h2_0, pow0);

    bip110_compute_h1(&hdr1, h1_1);
    bip110_compute_h2(h1_1, hdr1.m_mm_rhs, h2_1);
    bip110_compute_pow_hash(&hdr1, h2_1, pow1);

    assert(memcmp(pow0, pow1, 32) != 0);
    printf("Different profiles produce different hashes: PASS\n\n");
    return 0;
}

int main(void)
{
    printf("BIP-110 BLAKE2b V2 Header Tests\n");
    printf("================================\n\n");

    int fails = 0;

    fails += test_tagged_hash();
    fails += test_v2_header_creation();
    fails += test_v2_header_serialization();
    fails += test_v2_hash_computation();
    fails += test_v2_with_xor_key();
    fails += test_asic_profiles();

    printf("================================\n");
    if (fails == 0)
        printf("All tests PASSED\n");
    else
        printf("%d test(s) FAILED\n", fails);

    return fails;
}
