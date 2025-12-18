#ifndef RENESAS_CRYPTO_PRIMITIVES_H
#define RENESAS_CRYPTO_PRIMITIVES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "renesas_sha256.h"
#include "renesas_sha512.h"

typedef struct {
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    union {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256) || \
        defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        renesas_sha256_context sha256;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512) || \
        defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        renesas_sha512_context sha512;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224) || \
        defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256) || \
        defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384) || \
        defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
        renesas_sha3_context sha3;
#endif
    } MBEDTLS_PRIVATE(ctx);
} renesas_hash_operation_t;

#ifdef __cplusplus
}
#endif

#endif /* RENESAS_CRYPTO_PRIMITIVES_H */