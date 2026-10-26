// Reads BoringSSL's SHA-256 block dispatch through its pinned internal headers.
// Must mirror sha256_block_data_order in crypto/fipsmodule/sha/sha256.cc.inc.
#include "crypto/fipsmodule/sha/internal.h"

extern "C" const char *pq_bssl_sha256_backend(void) {
#if defined(OPENSSL_NO_ASM)
  return "boringssl-sha256/c";
#else
#if defined(SHA256_ASM_HW)
  if (bssl::sha256_hw_capable()) return "boringssl-sha256/hw";
#endif
#if defined(SHA256_ASM_AVX)
  if (bssl::sha256_avx_capable()) return "boringssl-sha256/avx";
#endif
#if defined(SHA256_ASM_SSSE3)
  if (bssl::sha256_ssse3_capable()) return "boringssl-sha256/ssse3";
#endif
#if defined(SHA256_ASM_NEON)
  if (bssl::CRYPTO_is_NEON_capable()) return "boringssl-sha256/neon";
#endif
  return "boringssl-sha256/nohw";
#endif
}
