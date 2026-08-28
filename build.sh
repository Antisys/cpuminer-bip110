#!/bin/bash
# =============================================================================
# build.sh - BIP-110 BLAKE2b V2 Miner build script
#
# Builds cpuminer-multi with the BIP-110 V2 header support and runs the
# self-tests. Works on Linux (Debian/Ubuntu). 
#
# Requirements:
#   build-essential autoconf automake libtool pkg-config
#   libssl-dev libcurl4-openssl-dev libjansson-dev libsodium-dev zlib1g-dev
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
step() { echo -e "${GREEN}=== $1 ===${NC}"; }
die()  { echo -e "${RED}ERROR: $1${NC}" >&2; exit 1; }

cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# Step 1: Check required tools
# ---------------------------------------------------------------------------
step "1/5 Abhängigkeiten prüfen"
for tool in gcc make autoconf automake libtoolize pkg-config; do
    command -v "$tool" >/dev/null 2>&1 || die "Tool '$tool' nicht gefunden. Installiere: sudo apt install build-essential autoconf automake libtool pkg-config"
done

# Check dev libraries (Debian/Ubuntu package names)
missing_libs=""
for pkg in libssl-dev libcurl4-openssl-dev libjansson-dev libsodium-dev zlib1g-dev; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing_libs="$missing_libs $pkg"
done
if [ -n "$missing_libs" ]; then
    die "Fehlende Dev-Pakete:$missing_libs. Installiere: sudo apt install$missing_libs"
fi
echo "  OK: alle Werkzeuge und Bibliotheken vorhanden."

# ---------------------------------------------------------------------------
# Step 2: Generate build system if not configured yet
# ---------------------------------------------------------------------------
step "2/5 Build-System konfigurieren"

# Detect CPU features for -march (only if compiler supports it)
march=""
if gcc -march=native -E -x c /dev/null >/dev/null 2>&1; then
    march="-march=native -mtune=native"
fi

if [ ! -f config.status ]; then
    echo "  autogen.sh läuft..."
    ./autogen.sh
    echo "  configure läuft..."
    ./configure --with-crypto --with-curl \
        CFLAGS="-O3 $march" \
        CXXFLAGS="-O3 $march" >/dev/null
else
    echo "  config.status vorhanden - überspringe configure. (make clean && ./build.sh force für Neu-Konfiguration)"
fi

# ---------------------------------------------------------------------------
# Step 3: Apply known LIBS fix (some distros don't detect all libs)
# ---------------------------------------------------------------------------
step "3/5 LIBS korrigieren"
REQUIRED_LIBS="-lz -lcurl -lssl -lcrypto -lsodium"
if grep -q "^LIBS = .*$REQUIRED_LIBS" Makefile 2>/dev/null; then
    echo "  LIBS bereits korrekt: $REQUIRED_LIBS"
else
    # Keep whatever configure set, append the required libs if missing
    if grep -q "^LIBS =" Makefile; then
        sed -i "s|^LIBS = .*|LIBS = $REQUIRED_LIBS|" Makefile
        echo "  LIBS auf '$REQUIRED_LIBS' gesetzt."
    else
        die "Makefile enthält keine LIBS-Zeile - configure schlug fehl."
    fi
fi

# ---------------------------------------------------------------------------
# Step 4: Compile
# ---------------------------------------------------------------------------
step "4/5 Kompilieren"
make clean >/dev/null 2>&1 || true
make -j"$(nproc)"
strip -s cpuminer 2>/dev/null || true
echo "  OK: ./cpuminer gebaut."

# ---------------------------------------------------------------------------
# Step 5: Self-tests
# ---------------------------------------------------------------------------
step "5/5 Selbsttests"
FAILED=0

echo "  Test: BIP-110 Vektoren (PR #359) ..."
gcc -O3 $march -o /tmp/test_bip110_vectors \
    test_bip110_vectors.c crypto/blake2b.c crypto/blake2b_v2.c \
    -I. -lssl -lcrypto 2>/dev/null || die "Kompilieren der Vektortests fehlgeschlagen"
if /tmp/test_bip110_vectors >/tmp/bip110_test.log 2>&1; then
    echo -e "    ${GREEN}PASS${NC}"
else
    echo -e "    ${RED}FAIL${NC} - siehe /tmp/bip110_test.log"
    FAILED=1
fi

echo "  Test: BLAKE2b V2 Unit-Tests ..."
(cd crypto && gcc -O3 $march -o /tmp/test_blake2b_v2 \
    ../test_blake2b_v2.c blake2b.c blake2b_v2.c \
    -I.. -I. -lssl -lcrypto 2>/dev/null)
if /tmp/test_blake2b_v2 >/tmp/blake2b_v2_test.log 2>&1; then
    echo -e "    ${GREEN}PASS${NC}"
else
    echo -e "    ${RED}FAIL${NC} - siehe /tmp/blake2b_v2_test.log"
    FAILED=1
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}Build successful - alle Tests bestanden.${NC}"
    echo "  Miner:   ./cpuminer --help"
    echo "  Version: $(git describe --tags 2>/dev/null || echo 'untagged')"
else
    echo -e "${RED}Build abgeschlossen, aber ${FAILED} Test(s) fehlgeschlagen.${NC}" >&2
    exit 1
fi
