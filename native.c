#include <oqs/oqs.h>
#include <string.h>

/* Access struct fields through the pinned C headers, not a Rust ABI replica. */
size_t pq_public_key_len(const OQS_SIG *sig) { return sig->length_public_key; }
size_t pq_secret_key_len(const OQS_SIG *sig) { return sig->length_secret_key; }
size_t pq_signature_len(const OQS_SIG *sig) { return sig->length_signature; }
unsigned int pq_category(const OQS_SIG *sig) { return sig->claimed_nist_level; }
const char *pq_algorithm_version(const OQS_SIG *sig) { return sig->alg_version; }

/* Mirrors verification dispatch in liboqs 0.16.0. build.sh enables every
 * parameter set in each family with the same architecture configuration. */
const char *pq_backend(const OQS_SIG *sig) {
    if (strncmp(sig->method_name, "ML-DSA-", 7) == 0) {
#if defined(OQS_ENABLE_SIG_ml_dsa_44_x86_64)
#if defined(OQS_DIST_BUILD)
        if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) &&
            OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&
            OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT))
#endif
            return "mldsa-native/x86_64";
#elif defined(OQS_ENABLE_SIG_ml_dsa_44_aarch64)
#if defined(OQS_DIST_BUILD)
        if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON))
#endif
            return "mldsa-native/aarch64";
#endif
        return "mldsa-native/C";
    }
    if (strncmp(sig->method_name, "Falcon-", 7) == 0) {
#if defined(OQS_ENABLE_SIG_falcon_512_avx2)
#if defined(OQS_DIST_BUILD)
        if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2))
#endif
            return "PQClean/avx2";
#elif defined(OQS_ENABLE_SIG_falcon_512_aarch64)
#if defined(OQS_DIST_BUILD)
        if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON))
#endif
            return "PQClean/aarch64";
#endif
        return "PQClean/clean";
    }
    return "slhdsa-c/portable";
}

int pq_dist_build(void) {
#if defined(OQS_DIST_BUILD)
    return 1;
#else
    return 0;
#endif
}

/* Mirrors Keccak dispatch in liboqs 0.16.0 common/sha3/xkcp_sha3.c, used by
 * ML-DSA and Falcon. slhdsa-c bundles its own scalar SHA-2 and Keccak. */
const char *pq_sha3_backend(void) {
#if defined(OQS_DIST_X86_64_BUILD) && defined(OQS_ENABLE_SHA3_xkcp_low_avx2)
#if defined(OQS_USE_SHA3_AVX512VL)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX512))
        return "xkcp/avx512vl";
#endif
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2))
        return "xkcp/avx2";
    return "xkcp/plain64";
#elif defined(OQS_ENABLE_SHA3_xkcp_low_avx2)
    return "xkcp/avx2";
#else
    return "xkcp/plain64";
#endif
}
