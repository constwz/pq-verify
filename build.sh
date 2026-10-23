#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
revision=5a1a854b0dc9f2141bdc771c555ee60c37950183 # liboqs 0.16.0
bssl_revision=af41e135bc1714981fb8a791e9dda4fc6ff140c3 # BoringSSL main, 2026-10-21
mode=${1:-optimized}
case "$mode" in
  optimized) dist=ON; bssl_no_asm=0 ;;
  portable) dist=OFF; bssl_no_asm=1 ;;
  *) echo "usage: $0 [optimized|portable]" >&2; exit 2 ;;
esac
cmake_args=(-DOQS_DIST_BUILD="$dist")
if [[ "$mode" == portable ]]; then
  # liboqs's generic ARM target still detects NEON/crypto extensions by default.
  for extension in ADX AES AVX AVX2 AVX512 AVX512BW AVX512DQ AVX512F \
      VPCLMULQDQ BMI1 BMI2 FMA PCLMULQDQ POPCNT SSE SSE2 SSE3 \
      ARM_AES ARM_SHA2 ARM_SHA3 ARM_NEON; do
    cmake_args+=("-DOQS_USE_${extension}_INSTRUCTIONS=OFF")
  done
fi
source_dir=${PQ_OQS_SOURCE:-"$root/target/liboqs-source"}
build_dir="$root/target/oqs-$mode"
mkdir -p "$root/target"
if [[ ! -d "$source_dir" ]]; then
  git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git "$source_dir"
fi
[[ $(git -C "$source_dir" rev-parse HEAD) == "$revision" ]] || {
  echo "liboqs must be pinned to $revision" >&2; exit 1;
}
[[ -z $(git -C "$source_dir" status --porcelain) ]] || {
  echo "liboqs source must be clean" >&2; exit 1;
}
algorithms='SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_falcon_512;SIG_falcon_1024'
for hash in sha2 shake; do
  for level in 128 192 256; do
    for variant in s f; do
      algorithms+=";SIG_slh_dsa_pure_${hash}_${level}${variant}"
    done
  done
done
# Cached conditional backend options otherwise survive changes in CPU switches.
cmake --fresh -S "$source_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
  -DOQS_OPT_TARGET=generic -DOQS_MINIMAL_BUILD="$algorithms" "${cmake_args[@]}"
if [[ "$mode" == portable ]] && \
    grep -Eq '^#define OQS_ENABLE_SIG_(ml_dsa_.*_(x86_64|aarch64)|falcon_.*_(avx2|aarch64)) ' \
    "$build_dir/include/oqs/oqsconfig.h"; then
  echo "portable build unexpectedly enabled an optimized signature backend" >&2
  exit 1
fi
cmake --build "$build_dir" --parallel "${PQ_BUILD_JOBS:-4}"

bssl_source=${PQ_BSSL_SOURCE:-"$root/target/boringssl-source"}
bssl_build="$root/target/bssl-$mode"
if [[ ! -d "$bssl_source" ]]; then
  git init -q "$bssl_source"
  git -C "$bssl_source" fetch -q --depth 1 https://github.com/google/boringssl.git "$bssl_revision"
  git -C "$bssl_source" checkout -q FETCH_HEAD
fi
[[ $(git -C "$bssl_source" rev-parse HEAD) == "$bssl_revision" ]] || {
  echo "BoringSSL must be pinned to $bssl_revision" >&2; exit 1;
}
[[ -z $(git -C "$bssl_source" status --porcelain) ]] || {
  echo "BoringSSL source must be clean" >&2; exit 1;
}
# PIC as in liboqs: Rust links PIE executables, and GCC without default PIE
# (RHEL family) otherwise rejects BoringSSL's absolute relocations.
bssl_args=(-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
if [[ $bssl_no_asm == 1 ]]; then
  # Portable mode: C SHA-256 only, matching liboqs's disabled CPU extensions.
  bssl_args+=(-DOPENSSL_NO_ASM=1)
fi
CC=${CC:-cc} CXX=${CXX:-c++} cmake --fresh -S "$bssl_source" -B "$bssl_build" "${bssl_args[@]}"
cmake --build "$bssl_build" --target crypto --parallel "${PQ_BUILD_JOBS:-4}"
printf 'source=%s\nbuild=%s\nno_asm=%s\nrevision=%s\n' \
  "$bssl_source" "$bssl_build" "$bssl_no_asm" "$bssl_revision" > "$build_dir/boringssl.txt"

{
  echo "liboqs_revision=$revision"
  echo "mode=$mode"
  echo "openssl=OFF"
  echo "dispatch=$dist"
  echo "source=$source_dir"
  echo "build=$build_dir"
  git -C "$source_dir" log -1 --format='commit_date=%cI'
  cat "$build_dir/CMakeCache.txt"
  echo "boringssl_revision=$bssl_revision"
  echo "boringssl_no_asm=$bssl_no_asm"
  cat "$bssl_build/CMakeCache.txt"
} > "$build_dir/provenance.txt"
CARGO_TARGET_DIR="$root/target" PQ_OQS_BUILD="$build_dir" \
  cargo build --manifest-path "$root/Cargo.toml" --release --offline
cp "$root/target/release/pq-verify-bench" "$root/target/pq-verify-$mode"
echo "Built $root/target/pq-verify-$mode" >&2
