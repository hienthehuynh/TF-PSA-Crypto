/*
 *  PSA hashing layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "renesas_driver_entrypoints.h"

#include <mbedtls/private/error_common.h>
#include <string.h>

#if defined(RENESAS_ACCEL_DRIVER)

psa_status_t renesas_hash_abort(
    renesas_hash_operation_t *operation)
{
    switch (operation->alg) {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            renesas_sha256_free(&operation->ctx.sha256);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            renesas_sha256_free(&operation->ctx.sha256);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            renesas_sha512_free(&operation->ctx.sha512);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            renesas_sha512_free(&operation->ctx.sha512);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
        case PSA_ALG_SHA3_224:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
        case PSA_ALG_SHA3_256:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
        case PSA_ALG_SHA3_384:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
        case PSA_ALG_SHA3_512:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224) || \
            defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256) || \
            defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384) || \
            defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
            renesas_sha3_free(&operation->ctx.sha3);
            break;
#endif
        default:
            return PSA_ERROR_BAD_STATE;
    }
    operation->alg = 0;
    return PSA_SUCCESS;
}

psa_status_t renesas_hash_setup(
    renesas_hash_operation_t *operation,
    psa_algorithm_t alg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    switch (alg) {
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            renesas_sha256_init(&operation->ctx.sha256);
            ret = renesas_sha256_starts(&operation->ctx.sha256, 1);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            renesas_sha256_init(&operation->ctx.sha256);
            ret = renesas_sha256_starts(&operation->ctx.sha256, 0);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            renesas_sha512_init(&operation->ctx.sha512);
            ret = renesas_sha512_starts(&operation->ctx.sha512, 1);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            renesas_sha512_init(&operation->ctx.sha512);
            ret = renesas_sha512_starts(&operation->ctx.sha512, 0);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
        case PSA_ALG_SHA3_224:
            renesas_sha3_init(&operation->ctx.sha3);
            ret = renesas_sha3_starts(&operation->ctx.sha3, MBEDTLS_SHA3_224);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
        case PSA_ALG_SHA3_256:
            renesas_sha3_init(&operation->ctx.sha3);
            ret = renesas_sha3_starts(&operation->ctx.sha3, MBEDTLS_SHA3_256);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
        case PSA_ALG_SHA3_384:
            renesas_sha3_init(&operation->ctx.sha3);
            ret = renesas_sha3_starts(&operation->ctx.sha3, MBEDTLS_SHA3_384);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
        case PSA_ALG_SHA3_512:
            renesas_sha3_init(&operation->ctx.sha3);
            ret = renesas_sha3_starts(&operation->ctx.sha3, MBEDTLS_SHA3_512);
            break;
#endif
        default:
            return PSA_ALG_IS_HASH(alg) ?
                   PSA_ERROR_NOT_SUPPORTED :
                   PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ret == 0) {
        operation->alg = alg;
    } else {
        renesas_hash_abort(operation);
    }
    return mbedtls_to_psa_error(ret);
}

psa_status_t renesas_hash_clone(
    const renesas_hash_operation_t *source_operation,
    renesas_hash_operation_t *target_operation)
{
    switch (source_operation->alg) {
        case 0:
            return PSA_ERROR_BAD_STATE;
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            renesas_sha256_clone(&target_operation->ctx.sha256,
                                 &source_operation->ctx.sha256);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            renesas_sha256_clone(&target_operation->ctx.sha256,
                                 &source_operation->ctx.sha256);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            renesas_sha512_clone(&target_operation->ctx.sha512,
                                 &source_operation->ctx.sha512);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            renesas_sha512_clone(&target_operation->ctx.sha512,
                                 &source_operation->ctx.sha512);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
        case PSA_ALG_SHA3_224:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
        case PSA_ALG_SHA3_256:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
        case PSA_ALG_SHA3_384:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
        case PSA_ALG_SHA3_512:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224) || \
            defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256) || \
            defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384) || \
            defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
            renesas_sha3_clone(&target_operation->ctx.sha3,
                               &source_operation->ctx.sha3);
            break;
#endif
        default:
            (void) source_operation;
            (void) target_operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    target_operation->alg = source_operation->alg;
    return PSA_SUCCESS;
}

psa_status_t renesas_hash_update(
    renesas_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch (operation->alg) {
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            ret = renesas_sha256_update(&operation->ctx.sha256,
                                        input, input_length);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            ret = renesas_sha256_update(&operation->ctx.sha256,
                                        input, input_length);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            ret = renesas_sha512_update(&operation->ctx.sha512,
                                        input, input_length);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            ret = renesas_sha512_update(&operation->ctx.sha512,
                                        input, input_length);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
        case PSA_ALG_SHA3_224:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
        case PSA_ALG_SHA3_256:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
        case PSA_ALG_SHA3_384:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
        case PSA_ALG_SHA3_512:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
    ret = renesas_sha3_update(&operation->ctx.sha3,
                              input, input_length);
    break;
#endif
        default:
            (void) input;
            (void) input_length;
            return PSA_ERROR_BAD_STATE;
    }

    return mbedtls_to_psa_error(ret);
}

psa_status_t renesas_hash_finish(
    renesas_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t actual_hash_length = PSA_HASH_LENGTH(operation->alg);

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = hash_size;
    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if (hash_size != 0) {
        memset(hash, '!', hash_size);
    }

    if (hash_size < actual_hash_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    switch (operation->alg) {
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            ret = renesas_sha256_finish(&operation->ctx.sha256, hash);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            ret = renesas_sha256_finish(&operation->ctx.sha256, hash);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            ret = renesas_sha512_finish(&operation->ctx.sha512, hash);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            ret = renesas_sha512_finish(&operation->ctx.sha512, hash);
            break;
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224)
        case PSA_ALG_SHA3_224:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256)
        case PSA_ALG_SHA3_256:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384)
        case PSA_ALG_SHA3_384:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
        case PSA_ALG_SHA3_512:
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_224) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_256) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_384) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_SHA3_512)
    ret = renesas_sha3_finish(&operation->ctx.sha3, hash, hash_size);
    break;
#endif
        default:
            (void) hash;
            return PSA_ERROR_BAD_STATE;
    }
    status = mbedtls_to_psa_error(ret);

exit:
    if (status == PSA_SUCCESS) {
        *hash_length = actual_hash_length;
    }
    return status;
}

psa_status_t renesas_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    renesas_hash_operation_t operation = MBEDTLS_PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = hash_size;
    status = renesas_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    status = renesas_hash_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    status = renesas_hash_finish(&operation, hash, hash_size, hash_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

exit:
    abort_status = renesas_hash_abort(&operation);
    if (status == PSA_SUCCESS) {
        return abort_status;
    } else {
        return status;
    }

}
#endif /* RENESAS_ACCEL_DRIVER */

#endif /* MBEDTLS_PSA_CRYPTO_C */
