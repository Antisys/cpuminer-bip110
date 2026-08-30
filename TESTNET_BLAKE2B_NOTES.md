# BLAKE2b Testnet Mining — Lessons Learned

Practical notes from connecting a CPU miner to the BIP-110 BLAKE2b testnet
(Bitcoin Knots PR #359, RC3, testnet4). These reflect what we learned the hard
way — not the BIP-110 spec itself, but how the pieces actually behave in the
wild.

## The chain

* Testnet4 with BLAKE2b activated at **block 150027, headline `Catbus` (RC3)**.
  Every release candidate changes both parameters: RC2 was `Totoro`/149537,
  RC3 is `Catbus`/150027. The headline is consensus-critical and must appear
  verbatim in the coinbase scriptSig.
* It is a **separate chain**, not the regular testnet4. You must sync against
  BLAKE2b peers; the DNS seeds serve the SHA256d chain and you end up on the
  wrong fork.
* Block hash is three stages:
  1. `h1` = TaggedHash — **SHA256** (BIP-340 style), not BLAKE2b
  2. `h2` = TaggedHash("Merge-mining hook") over `h1 ‖ zeros ‖ mm_rhs`
  3. final PoW = **BLAKE2b-256** over the ASIC input, optional XOR mask
* The PoW is designed for **Sia-ASIC compatibility** — hence the 80-byte
  Sia-style work layout.

## The node

* Use the **exact RC binaries** (official RC3 from `test.bitcoinknots.org`,
  not a self build). An RC2 build cannot even sync the RC3 chain: header sync
  stops exactly at the RC2 activation boundary (149536).
* Sync only works with the BLAKE2b seeds; activation height + headline are the
  critical consensus parameters (`blake2b_headline=Catbus` in bitcoin.conf).

## BLAKE2b CPU mining

* Expect **~10-13 MH/s on 8 threads** (i5-8365U) versus Sia ASICs in the TH/s
  range. CPU mining on this chain is a correctness test, not real mining.
* The DATUM gateway serves work in **Sia-style Stratum**: commitment `coinb1`
  (39 bytes), `merkle=[]`, **8-byte `ntime8`**.
* 80-byte work header:
  `prevblock_hidden(32) + nonce8(8) + ntime8(8) + root(32)`.
* **`prevblock_hidden` is precomputed by the gateway** and sent directly as the
  notify "prevhash". Do not hash it again — that was the key integration trap.
* `root` = `BLAKE2b(0x00 ‖ coinb1 ‖ extranonce)`, extranonce = xnonce1 + xnonce2.
* Block hash = `BLAKE2b(work80) XOR mask`, **byte-reversed** (LE) before the
  target comparison.
* **diff 1 ≈ 8 min/share at 10 MH/s, but blocks arrive every ~40 s** — most
  CPU shares are stale. With a correct hash you get occasional accepts, but the
  economics are irrelevant; treat it as an end-to-end validation, not a way to
  find blocks.

## Integration summary

Verified end-to-end: Node (RC3) → DATUM gateway → CPU miner finds valid
BLAKE2b shares → gateway accepts them. The gateway sends the prevblock_hidden
pre-computed; matching its byte order (digest reversal) and using the notify
prevhash verbatim was what made shares valid.
