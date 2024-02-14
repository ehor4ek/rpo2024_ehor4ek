#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_pk.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/main_test.function
 *      Platform code file  : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/host_test.function
 *      Helper file         : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/helpers.function
 *      Test suite file     : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function
 *      Test suite data     : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.data
 *
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

#include "mbedtls/build_info.h"

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/arguments.h>
#include <test/helpers.h>
#include <test/macros.h>
#include <test/random.h>
#include <test/bignum_helpers.h>
#include <test/psa_crypto_helpers.h>
#include <test/threading_helpers.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_ERROR_C)
#include "mbedtls/error.h"
#endif
#include "mbedtls/platform.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

/*----------------------------------------------------------------------------*/
/* Global variables */

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
    (!defined(MBEDTLS_NO_PLATFORM_ENTROPY) ||      \
    defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||    \
    defined(ENTROPY_NV_SEED))
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output(FILE *out_stream, const char *path)
{
    int out_fd, dup_fd;
    FILE *path_stream;

    out_fd = fileno(out_stream);
    dup_fd = dup(out_fd);

    if (dup_fd == -1) {
        return -1;
    }

    path_stream = fopen(path, "w");
    if (path_stream == NULL) {
        close(dup_fd);
        return -1;
    }

    fflush(out_stream);
    if (dup2(fileno(path_stream), out_fd) == -1) {
        close(dup_fd);
        fclose(path_stream);
        return -1;
    }

    fclose(path_stream);
    return dup_fd;
}

static int restore_output(FILE *out_stream, int dup_fd)
{
    int out_fd = fileno(out_stream);

    fflush(out_stream);
    if (dup2(dup_fd, out_fd) == -1) {
        close(out_fd);
        close(dup_fd);
        return -1;
    }

    close(dup_fd);
    return 0;
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 43 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_PK_C)
#line 2 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
#include "mbedtls/pk.h"
#include "pk_internal.h"

/* For error codes */
#include "mbedtls/asn1.h"
#include "mbedtls/base64.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "pk_internal.h"

#include <limits.h>
#include <stdint.h>

/* Needed only for test case data under #if defined(MBEDTLS_USE_PSA_CRYPTO),
 * but the test code generator requires test case data to be valid C code
 * unconditionally (https://github.com/Mbed-TLS/mbedtls/issues/2023). */
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"

/* Used for properly sizing the key buffer in pk_genkey_ec() */
#include "psa_util_internal.h"

#define RSA_KEY_SIZE   MBEDTLS_RSA_GEN_KEY_MIN_BITS
#define RSA_KEY_LEN   (MBEDTLS_RSA_GEN_KEY_MIN_BITS/8)

/* MBEDTLS_TEST_PK_PSA_SIGN is enabled when:
 * - The build has PK_[PARSE/WRITE]_C for RSA or ECDSA signature.
 * - The build has built-in ECC and ECDSA signature.
 */
#if (defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_PK_WRITE_C) && \
    ((defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)) || \
    defined(MBEDTLS_PK_CAN_ECDSA_SIGN))) || \
    (defined(MBEDTLS_ECP_C) && defined(MBEDTLS_PK_CAN_ECDSA_SIGN))
#define MBEDTLS_TEST_PK_PSA_SIGN
#endif

/* MBEDTLS_TEST_PSA_ECC_AT_LEAST_ONE_CURVE is enabled when PSA supports
 * at least one elliptic curve. This is distinct from
 * PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY because that symbol can be enabled even
 * when there are no curves. This happens in particular in a configuration
 * with MBEDTLS_PSA_CRYPTO_CONFIG disabled and where the only legacy curve
 * is secp224k1, which is not supported in PSA. */
#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256) || \
    defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384) || \
    defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512) || \
    defined(PSA_WANT_ECC_MONTGOMERY_255) || \
    defined(PSA_WANT_ECC_MONTGOMERY_448) || \
    defined(PSA_WANT_ECC_SECP_K1_192) || \
    defined(PSA_WANT_ECC_SECP_K1_224) || \
    defined(PSA_WANT_ECC_SECP_K1_256) || \
    defined(PSA_WANT_ECC_SECP_R1_192) || \
    defined(PSA_WANT_ECC_SECP_R1_224) || \
    defined(PSA_WANT_ECC_SECP_R1_256) || \
    defined(PSA_WANT_ECC_SECP_R1_384) || \
    defined(PSA_WANT_ECC_SECP_R1_521)
#define MBEDTLS_TEST_PSA_ECC_AT_LEAST_ONE_CURVE
#endif
#endif

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static int pk_genkey_ec(mbedtls_pk_context *pk, mbedtls_ecp_group_id grp_id)
{
    psa_status_t status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t curve_bits;
    psa_ecc_family_t curve = mbedtls_ecc_group_to_psa(grp_id, &curve_bits);
    int ret;

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    psa_set_key_bits(&key_attr, curve_bits);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT |
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_SIGN_MESSAGE);
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_ANY_HASH));
#else
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
#endif

    status = psa_generate_key(&key_attr, &pk->priv_id);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = psa_export_public_key(pk->priv_id, pk->pub_raw, sizeof(pk->pub_raw),
                                   &pk->pub_raw_len);
    if (status != PSA_SUCCESS) {
        ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        goto exit;
    }

    pk->ec_family = curve;
    pk->ec_bits = curve_bits;

    return 0;

exit:
    status = psa_destroy_key(pk->priv_id);
    return (ret != 0) ? ret : psa_pk_status_to_mbedtls(status);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

/** Generate a key of the desired type.
 *
 * \param pk               The PK object to fill. It must have been initialized
 *                         with mbedtls_pk_setup().
 * \param curve_or_keybits - For RSA keys, the key size in bits.
 *                         - For EC keys, the curve (\c MBEDTLS_ECP_DP_xxx).
 *
 * \return                 The status from the underlying type-specific key
 *                         generation function.
 * \return                 -1 if the key type is not recognized.
 */
static int pk_genkey(mbedtls_pk_context *pk, int curve_or_keybits)
{
    (void) pk;
    (void) curve_or_keybits;

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if (mbedtls_pk_get_type(pk) == MBEDTLS_PK_RSA) {
        return mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk),
                                   mbedtls_test_rnd_std_rand, NULL,
                                   curve_or_keybits, 3);
    }
#endif
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    if (mbedtls_pk_get_type(pk) == MBEDTLS_PK_ECKEY ||
        mbedtls_pk_get_type(pk) == MBEDTLS_PK_ECKEY_DH ||
        mbedtls_pk_get_type(pk) == MBEDTLS_PK_ECDSA) {
        int ret;

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
        ret = pk_genkey_ec(pk, curve_or_keybits);
        if (ret != 0) {
            return ret;
        }

        return 0;
#else
        ret = mbedtls_ecp_group_load(&mbedtls_pk_ec_rw(*pk)->grp, curve_or_keybits);
        if (ret != 0) {
            return ret;
        }
        return mbedtls_ecp_gen_keypair(&mbedtls_pk_ec_rw(*pk)->grp,
                                       &mbedtls_pk_ec_rw(*pk)->d,
                                       &mbedtls_pk_ec_rw(*pk)->Q,
                                       mbedtls_test_rnd_std_rand, NULL);
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

    }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
    return -1;
}

#if defined(MBEDTLS_PSA_CRYPTO_C)
static psa_key_usage_t pk_get_psa_attributes_implied_usage(
    psa_key_usage_t expected_usage)
{
    /* Usage implied universally */
    if (expected_usage & PSA_KEY_USAGE_SIGN_HASH) {
        expected_usage |= PSA_KEY_USAGE_SIGN_MESSAGE;
    }
    if (expected_usage & PSA_KEY_USAGE_VERIFY_HASH) {
        expected_usage |= PSA_KEY_USAGE_VERIFY_MESSAGE;
    }
    /* Usage implied by mbedtls_pk_get_psa_attributes() */
    if (expected_usage & PSA_KEY_USAGE_SIGN_HASH) {
        expected_usage |= PSA_KEY_USAGE_VERIFY_HASH;
    }
    if (expected_usage & PSA_KEY_USAGE_SIGN_MESSAGE) {
        expected_usage |= PSA_KEY_USAGE_VERIFY_MESSAGE;
    }
    if (expected_usage & PSA_KEY_USAGE_DECRYPT) {
        expected_usage |= PSA_KEY_USAGE_ENCRYPT;
    }
    expected_usage |= PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY;
    return expected_usage;
}
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(MBEDTLS_RSA_C)
int mbedtls_rsa_decrypt_func(void *ctx, size_t *olen,
                             const unsigned char *input, unsigned char *output,
                             size_t output_max_len)
{
    return mbedtls_rsa_pkcs1_decrypt((mbedtls_rsa_context *) ctx,
                                     mbedtls_test_rnd_std_rand, NULL,
                                     olen, input, output, output_max_len);
}
int mbedtls_rsa_sign_func(void *ctx,
                          int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                          mbedtls_md_type_t md_alg, unsigned int hashlen,
                          const unsigned char *hash, unsigned char *sig)
{
    ((void) f_rng);
    ((void) p_rng);
    return mbedtls_rsa_pkcs1_sign((mbedtls_rsa_context *) ctx,
                                  mbedtls_test_rnd_std_rand, NULL,
                                  md_alg, hashlen, hash, sig);
}
size_t mbedtls_rsa_key_len_func(void *ctx)
{
    return ((const mbedtls_rsa_context *) ctx)->len;
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PK_HAVE_ECC_KEYS)
static mbedtls_ecp_group_id ecc_pick_grp_id(void)
{
#if defined(MBEDTLS_ECP_LIGHT)
    return mbedtls_ecp_grp_id_list()[0];
#elif defined(PSA_WANT_ECC_SECP_R1_192)
    return MBEDTLS_ECP_DP_SECP192R1;
#elif defined(PSA_WANT_ECC_SECP_R1_224)
    return MBEDTLS_ECP_DP_SECP224R1;
#elif defined(PSA_WANT_ECC_SECP_R1_256)
    return MBEDTLS_ECP_DP_SECP256R1;
#elif defined(PSA_WANT_ECC_SECP_R1_384)
    return MBEDTLS_ECP_DP_SECP384R1;
#elif defined(PSA_WANT_ECC_SECP_R1_521)
    return MBEDTLS_ECP_DP_SECP521R1;
#elif defined(PSA_WANT_ECC_SECP_K1_192)
    return MBEDTLS_ECP_DP_SECP192K1;
#elif defined(PSA_WANT_ECC_SECP_K1_224)
    return MBEDTLS_ECP_DP_SECP224K1;
#elif defined(PSA_WANT_ECC_SECP_K1_256)
    return MBEDTLS_ECP_DP_SECP256K1;
#elif defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
    return MBEDTLS_ECP_DP_BP256R1;
#elif defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
    return MBEDTLS_ECP_DP_BP384R1;
#elif defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
    return MBEDTLS_ECP_DP_BP512R1;
#elif defined(PSA_WANT_ECC_MONTGOMERY_255)
    return MBEDTLS_ECP_DP_CURVE25519;
#elif defined(PSA_WANT_ECC_MONTGOMERY_448)
    return MBEDTLS_ECP_DP_CURVE448;
#else
    return 0;
#endif
}
#endif /* defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PK_HAVE_ECC_KEYS) */

#if defined(MBEDTLS_PSA_CRYPTO_C)
static int pk_setup_for_type(mbedtls_pk_type_t pk_type, int want_pair,
                             mbedtls_pk_context *pk, psa_key_type_t *psa_type)
{
    if (pk_type == MBEDTLS_PK_NONE) {
        return 0;
    }
    TEST_EQUAL(mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(pk_type)), 0);

    switch (pk_type) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
        {
            *psa_type = PSA_KEY_TYPE_RSA_KEY_PAIR;
            mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*pk);
            if (want_pair) {
#if defined(MBEDTLS_GENPRIME)
                TEST_EQUAL(mbedtls_rsa_gen_key(
                               rsa,
                               mbedtls_test_rnd_std_rand, NULL,
                               MBEDTLS_RSA_GEN_KEY_MIN_BITS, 65537), 0);
#else
                TEST_FAIL("I don't know how to create an RSA key pair in this configuration.");
#endif
            } else {
                unsigned char N[PSA_BITS_TO_BYTES(MBEDTLS_RSA_GEN_KEY_MIN_BITS)] = { 0xff };
                N[sizeof(N) - 1] = 0x03;
                const unsigned char E[1] = { 0x03 };
                TEST_EQUAL(mbedtls_rsa_import_raw(rsa,
                                                  N, sizeof(N),
                                                  NULL, 0, NULL, 0, NULL, 0,
                                                  E, sizeof(E)), 0);
                TEST_EQUAL(mbedtls_rsa_complete(rsa), 0);
            }
            break;
        }
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
        {
            mbedtls_ecp_group_id grp_id = ecc_pick_grp_id();
            size_t bits;
            *psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(mbedtls_ecc_group_to_psa(grp_id, &bits));
            TEST_EQUAL(pk_genkey(pk, grp_id), 0);
            if (!want_pair) {
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
                psa_key_attributes_t pub_attributes = PSA_KEY_ATTRIBUTES_INIT;
                psa_set_key_type(&pub_attributes,
                                 PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(*psa_type));
                psa_set_key_usage_flags(&pub_attributes,
                                        PSA_KEY_USAGE_EXPORT |
                                        PSA_KEY_USAGE_COPY |
                                        PSA_KEY_USAGE_VERIFY_MESSAGE |
                                        PSA_KEY_USAGE_VERIFY_HASH);
                psa_set_key_algorithm(&pub_attributes, PSA_ALG_ECDSA_ANY);
                PSA_ASSERT(psa_destroy_key(pk->priv_id));
                pk->priv_id = MBEDTLS_SVC_KEY_ID_INIT;
#else
                mbedtls_ecp_keypair *ec = mbedtls_pk_ec_rw(*pk);
                mbedtls_mpi_free(&ec->d);
#endif
            }
            break;
        }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

        default:
            TEST_FAIL("Unknown PK type in test data");
            break;
    }

    if (!want_pair) {
        *psa_type = PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(*psa_type);
    }
    return 0;

exit:
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)

/*
 * Generate an ECC key using PSA and return the key identifier of that key,
 * or 0 if the key generation failed.
 * The key uses NIST P-256 and is usable for signing with SHA-256.
 */
mbedtls_svc_key_id_t pk_psa_genkey_ecc(void)
{
    mbedtls_svc_key_id_t key;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const psa_key_type_t type =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    const size_t bits = 256;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, bits);
    PSA_ASSERT(psa_generate_key(&attributes, &key));

exit:
    return key;
}

/*
 * Generate an RSA key using PSA and return the key identifier of that key,
 * or 0 if the key generation failed.
 */
mbedtls_svc_key_id_t pk_psa_genkey_rsa(void)
{
    mbedtls_svc_key_id_t key;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const psa_key_type_t type = PSA_KEY_TYPE_RSA_KEY_PAIR;
    const size_t bits = 1024;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, bits);
    PSA_ASSERT(psa_generate_key(&attributes, &key));

exit:
    return key;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#line 389 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_psa_utils(int key_is_rsa)
{
    mbedtls_pk_context pk, pk2;
    mbedtls_svc_key_id_t key;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    const char * const name = "Opaque";
    size_t bitlen;

    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    unsigned char b1[1], b2[1];
    size_t len;
    mbedtls_pk_debug_item dbg;

    mbedtls_pk_init(&pk);
    mbedtls_pk_init(&pk2);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_setup_opaque(&pk, MBEDTLS_SVC_KEY_ID_INIT) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    mbedtls_pk_free(&pk);
    mbedtls_pk_init(&pk);

    if (key_is_rsa) {
        bitlen = 1024; /* hardcoded in genkey() */
        key = pk_psa_genkey_rsa();
    } else {
        bitlen = 256; /* hardcoded in genkey() */
        key = pk_psa_genkey_ecc();
    }
    if (mbedtls_svc_key_id_is_null(key)) {
        goto exit;
    }

    TEST_ASSERT(mbedtls_pk_setup_opaque(&pk, key) == 0);

    TEST_ASSERT(mbedtls_pk_get_type(&pk) == MBEDTLS_PK_OPAQUE);
    TEST_ASSERT(strcmp(mbedtls_pk_get_name(&pk), name) == 0);

    TEST_ASSERT(mbedtls_pk_get_bitlen(&pk) == bitlen);
    TEST_ASSERT(mbedtls_pk_get_len(&pk) == bitlen / 8);

    if (key_is_rsa) {
        TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY) == 0);
        TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA) == 0);
        TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA) == 1);
    } else {
        TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY) == 1);
        TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA) == 1);
        TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA) == 0);
    }

    /* unsupported operations: verify, decrypt, encrypt */
    if (key_is_rsa == 1) {
        TEST_ASSERT(mbedtls_pk_verify(&pk, md_alg,
                                      b1, sizeof(b1), b2, sizeof(b2))
                    == MBEDTLS_ERR_PK_TYPE_MISMATCH);
    } else {
        TEST_ASSERT(mbedtls_pk_decrypt(&pk, b1, sizeof(b1),
                                       b2, &len, sizeof(b2),
                                       NULL, NULL)
                    == MBEDTLS_ERR_PK_TYPE_MISMATCH);
    }
    TEST_ASSERT(mbedtls_pk_encrypt(&pk, b1, sizeof(b1),
                                   b2, &len, sizeof(b2),
                                   NULL, NULL)
                == MBEDTLS_ERR_PK_TYPE_MISMATCH);

    /* unsupported functions: check_pair, debug */
    if (key_is_rsa) {
        TEST_ASSERT(mbedtls_pk_setup(&pk2,
                                     mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    } else {
        TEST_ASSERT(mbedtls_pk_setup(&pk2,
                                     mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0);
    }
    TEST_ASSERT(mbedtls_pk_check_pair(&pk, &pk2,
                                      mbedtls_test_rnd_std_rand, NULL)
                == MBEDTLS_ERR_PK_TYPE_MISMATCH);
    TEST_ASSERT(mbedtls_pk_debug(&pk, &dbg)
                == MBEDTLS_ERR_PK_TYPE_MISMATCH);

    /* test that freeing the context does not destroy the key */
    mbedtls_pk_free(&pk);
    TEST_ASSERT(PSA_SUCCESS == psa_get_key_attributes(key, &attributes));
    TEST_ASSERT(PSA_SUCCESS == psa_destroy_key(key));

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    mbedtls_pk_free(&pk);   /* redundant except upon error */
    mbedtls_pk_free(&pk2);
    USE_PSA_DONE();
}

void test_pk_psa_utils_wrapper( void ** params )
{

    test_pk_psa_utils( ((mbedtls_test_argument_t *) params[0])->sint );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#line 491 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_can_do_ext(int opaque_key, int key_type, int key_usage, int key_alg,
                   int key_alg2, int curve_or_keybits, int alg_check, int usage_check,
                   int result)
{
    mbedtls_pk_context pk;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    if (opaque_key == 1) {
        psa_set_key_usage_flags(&attributes, key_usage);
        psa_set_key_algorithm(&attributes, key_alg);
        if (key_alg2 != 0) {
            psa_set_key_enrollment_algorithm(&attributes, key_alg2);
        }
        psa_set_key_type(&attributes, key_type);
        psa_set_key_bits(&attributes, curve_or_keybits);

        PSA_ASSERT(psa_generate_key(&attributes, &key));

        if (mbedtls_svc_key_id_is_null(key)) {
            goto exit;
        }

        TEST_EQUAL(mbedtls_pk_setup_opaque(&pk, key), 0);

        TEST_EQUAL(mbedtls_pk_get_type(&pk), MBEDTLS_PK_OPAQUE);
    } else {
        TEST_EQUAL(mbedtls_pk_setup(&pk,
                                    mbedtls_pk_info_from_type(key_type)), 0);
        TEST_EQUAL(pk_genkey(&pk, curve_or_keybits), 0);
        TEST_EQUAL(mbedtls_pk_get_type(&pk), key_type);
    }

    TEST_EQUAL(mbedtls_pk_can_do_ext(&pk, alg_check, usage_check), result);

exit:
    psa_reset_key_attributes(&attributes);
    PSA_ASSERT(psa_destroy_key(key));
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_can_do_ext_wrapper( void ** params )
{

    test_pk_can_do_ext( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#line 538 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_invalid_param(void)
{
    mbedtls_pk_context ctx;
    mbedtls_pk_type_t pk_type = 0;
    unsigned char buf[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    size_t buf_size = sizeof(buf);

    mbedtls_pk_init(&ctx);
    USE_PSA_INIT();

    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_verify_restartable(&ctx, MBEDTLS_MD_NONE,
                                             NULL, buf_size,
                                             buf, buf_size,
                                             NULL));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_verify_restartable(&ctx, MBEDTLS_MD_SHA256,
                                             NULL, 0,
                                             buf, buf_size,
                                             NULL));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_verify_ext(pk_type, NULL,
                                     &ctx, MBEDTLS_MD_NONE,
                                     NULL, buf_size,
                                     buf, buf_size));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_verify_ext(pk_type, NULL,
                                     &ctx, MBEDTLS_MD_SHA256,
                                     NULL, 0,
                                     buf, buf_size));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_sign_restartable(&ctx, MBEDTLS_MD_NONE,
                                           NULL, buf_size,
                                           buf, buf_size, &buf_size,
                                           NULL, NULL,
                                           NULL));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_sign_restartable(&ctx, MBEDTLS_MD_SHA256,
                                           NULL, 0,
                                           buf, buf_size, &buf_size,
                                           NULL, NULL,
                                           NULL));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_sign_ext(pk_type, &ctx, MBEDTLS_MD_NONE,
                                   NULL, buf_size,
                                   buf, buf_size, &buf_size,
                                   NULL, NULL));
    TEST_EQUAL(MBEDTLS_ERR_PK_BAD_INPUT_DATA,
               mbedtls_pk_sign_ext(pk_type, &ctx, MBEDTLS_MD_SHA256,
                                   NULL, 0,
                                   buf, buf_size, &buf_size,
                                   NULL, NULL));
exit:
    mbedtls_pk_free(&ctx);
    USE_PSA_DONE();
}

void test_pk_invalid_param_wrapper( void ** params )
{
    (void)params;

    test_pk_invalid_param(  );
}
#line 597 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_valid_parameters(void)
{
    mbedtls_pk_context pk;
    unsigned char buf[1];
    size_t len;
    void *options = NULL;

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_setup(&pk, NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    /* In informational functions, we accept NULL where a context pointer
     * is expected because that's what the library has done forever.
     * We do not document that NULL is accepted, so we may wish to change
     * the behavior in a future version. */
    TEST_ASSERT(mbedtls_pk_get_bitlen(NULL) == 0);
    TEST_ASSERT(mbedtls_pk_get_len(NULL) == 0);
    TEST_ASSERT(mbedtls_pk_can_do(NULL, MBEDTLS_PK_NONE) == 0);

    TEST_ASSERT(mbedtls_pk_sign_restartable(&pk,
                                            MBEDTLS_MD_NONE,
                                            NULL, 0,
                                            buf, sizeof(buf), &len,
                                            mbedtls_test_rnd_std_rand, NULL,
                                            NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_sign(&pk,
                                MBEDTLS_MD_NONE,
                                NULL, 0,
                                buf, sizeof(buf), &len,
                                mbedtls_test_rnd_std_rand, NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_sign_ext(MBEDTLS_PK_NONE, &pk,
                                    MBEDTLS_MD_NONE,
                                    NULL, 0,
                                    buf, sizeof(buf), &len,
                                    mbedtls_test_rnd_std_rand, NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_verify_restartable(&pk,
                                              MBEDTLS_MD_NONE,
                                              NULL, 0,
                                              buf, sizeof(buf),
                                              NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_verify(&pk,
                                  MBEDTLS_MD_NONE,
                                  NULL, 0,
                                  buf, sizeof(buf)) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_verify_ext(MBEDTLS_PK_NONE, options,
                                      &pk,
                                      MBEDTLS_MD_NONE,
                                      NULL, 0,
                                      buf, sizeof(buf)) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_encrypt(&pk,
                                   NULL, 0,
                                   NULL, &len, 0,
                                   mbedtls_test_rnd_std_rand, NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    TEST_ASSERT(mbedtls_pk_decrypt(&pk,
                                   NULL, 0,
                                   NULL, &len, 0,
                                   mbedtls_test_rnd_std_rand, NULL) ==
                MBEDTLS_ERR_PK_BAD_INPUT_DATA);

#if defined(MBEDTLS_PK_PARSE_C)
    TEST_ASSERT(mbedtls_pk_parse_key(&pk, NULL, 0, NULL, 1,
                                     mbedtls_test_rnd_std_rand, NULL) ==
                MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);

    TEST_ASSERT(mbedtls_pk_parse_public_key(&pk, NULL, 0) ==
                MBEDTLS_ERR_PK_KEY_INVALID_FORMAT);
#endif /* MBEDTLS_PK_PARSE_C */
    USE_PSA_DONE();
exit:
    ;
}

void test_valid_parameters_wrapper( void ** params )
{
    (void)params;

    test_valid_parameters(  );
}
#if defined(MBEDTLS_PK_WRITE_C)
#line 685 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_valid_parameters_pkwrite(data_t *key_data)
{
    mbedtls_pk_context pk;

    /* For the write tests to be effective, we need a valid key pair. */
    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_parse_key(&pk,
                                     key_data->x, key_data->len, NULL, 0,
                                     mbedtls_test_rnd_std_rand, NULL) == 0);

    TEST_ASSERT(mbedtls_pk_write_key_der(&pk, NULL, 0) ==
                MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);

    TEST_ASSERT(mbedtls_pk_write_pubkey_der(&pk, NULL, 0) ==
                MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);

#if defined(MBEDTLS_PEM_WRITE_C)
    TEST_ASSERT(mbedtls_pk_write_key_pem(&pk, NULL, 0) ==
                MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);

    TEST_ASSERT(mbedtls_pk_write_pubkey_pem(&pk, NULL, 0) ==
                MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
#endif /* MBEDTLS_PEM_WRITE_C */

exit:
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_valid_parameters_pkwrite_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_valid_parameters_pkwrite( &data0 );
}
#endif /* MBEDTLS_PK_WRITE_C */
#line 718 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_utils(int type, int curve_or_keybits, int bitlen, int len, char *name)
{
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(type)) == 0);
    TEST_ASSERT(pk_genkey(&pk, curve_or_keybits) == 0);

    TEST_ASSERT((int) mbedtls_pk_get_type(&pk) == type);
    TEST_ASSERT(mbedtls_pk_can_do(&pk, type));
    TEST_ASSERT(mbedtls_pk_get_bitlen(&pk) == (unsigned) bitlen);
    TEST_ASSERT(mbedtls_pk_get_len(&pk) == (unsigned) len);
    TEST_ASSERT(strcmp(mbedtls_pk_get_name(&pk), name) == 0);

exit:
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_utils_wrapper( void ** params )
{

    test_pk_utils( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4] );
}
#if defined(MBEDTLS_PK_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#line 741 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_mbedtls_pk_check_pair(char *pub_file, char *prv_file, int ret)
{
    mbedtls_pk_context pub, prv, alt;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t opaque_key_id = MBEDTLS_SVC_KEY_ID_INIT;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    mbedtls_pk_init(&pub);
    mbedtls_pk_init(&prv);
    mbedtls_pk_init(&alt);
    USE_PSA_INIT();

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    /* mbedtls_pk_check_pair() returns either PK or ECP error codes depending
       on MBEDTLS_USE_PSA_CRYPTO so here we dynamically translate between the
       two */
    if (ret == MBEDTLS_ERR_ECP_BAD_INPUT_DATA) {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    TEST_ASSERT(mbedtls_pk_parse_public_keyfile(&pub, pub_file) == 0);
    TEST_ASSERT(mbedtls_pk_parse_keyfile(&prv, prv_file, NULL,
                                         mbedtls_test_rnd_std_rand, NULL)
                == 0);

    TEST_ASSERT(mbedtls_pk_check_pair(&pub, &prv,
                                      mbedtls_test_rnd_std_rand, NULL)
                == ret);

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
    if (mbedtls_pk_get_type(&prv) == MBEDTLS_PK_RSA) {
        TEST_ASSERT(mbedtls_pk_setup_rsa_alt(&alt, mbedtls_pk_rsa(prv),
                                             mbedtls_rsa_decrypt_func, mbedtls_rsa_sign_func,
                                             mbedtls_rsa_key_len_func) == 0);
        TEST_ASSERT(mbedtls_pk_check_pair(&pub, &alt,
                                          mbedtls_test_rnd_std_rand, NULL)
                    == ret);
    }
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (mbedtls_pk_get_type(&prv) == MBEDTLS_PK_ECKEY) {
        TEST_EQUAL(mbedtls_pk_wrap_as_opaque(&prv, &opaque_key_id,
                                             PSA_ALG_ANY_HASH,
                                             PSA_KEY_USAGE_EXPORT, 0), 0);
        TEST_EQUAL(mbedtls_pk_check_pair(&pub, &prv, mbedtls_test_rnd_std_rand,
                                         NULL), ret);
    }
#endif

exit:
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_destroy_key(opaque_key_id);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    mbedtls_pk_free(&pub);
    mbedtls_pk_free(&prv);
    mbedtls_pk_free(&alt);
    USE_PSA_DONE();
}

void test_mbedtls_pk_check_pair_wrapper( void ** params )
{

    test_mbedtls_pk_check_pair( (char *) params[0], (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_PK_PARSE_C */
#if defined(MBEDTLS_RSA_C)
#line 803 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_verify_test_vec(data_t *message_str, int digest, int mod,
                            char *input_N, char *input_E,
                            data_t *result_str, int result)
{
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    mbedtls_pk_restart_ctx *rs_ctx = NULL;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_pk_restart_ctx ctx;

    rs_ctx = &ctx;
    mbedtls_pk_restart_init(rs_ctx);
    // this setting would ensure restart would happen if ECC was used
    mbedtls_ecp_set_max_ops(1);
#endif

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    rsa = mbedtls_pk_rsa(pk);

    rsa->len = mod / 8;
    TEST_ASSERT(mbedtls_test_read_mpi(&rsa->N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&rsa->E, input_E) == 0);

    TEST_ASSERT(mbedtls_pk_verify(&pk, digest, message_str->x, 0,
                                  result_str->x, mbedtls_pk_get_len(&pk)) == result);

    TEST_ASSERT(mbedtls_pk_verify_restartable(&pk, digest, message_str->x, 0,
                                              result_str->x, mbedtls_pk_get_len(
                                                  &pk), rs_ctx) == result);

exit:
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_pk_restart_free(rs_ctx);
#endif
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_rsa_verify_test_vec_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_pk_rsa_verify_test_vec( &data0, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4], (char *) params[5], &data6, ((mbedtls_test_argument_t *) params[8])->sint );
}
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_RSA_C)
#line 846 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_verify_ext_test_vec(data_t *message_str, int digest,
                                int mod, char *input_N,
                                char *input_E, data_t *result_str,
                                int pk_type, int mgf1_hash_id,
                                int salt_len, int sig_len,
                                int result)
{
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    mbedtls_pk_rsassa_pss_options pss_opts;
    void *options;
    int ret;

    mbedtls_pk_init(&pk);
    MD_OR_USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    rsa = mbedtls_pk_rsa(pk);

    rsa->len = mod / 8;
    TEST_ASSERT(mbedtls_test_read_mpi(&rsa->N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&rsa->E, input_E) == 0);


    if (mgf1_hash_id < 0) {
        options = NULL;
    } else {
        options = &pss_opts;

        pss_opts.mgf1_hash_id = mgf1_hash_id;
        pss_opts.expected_salt_len = salt_len;
    }

    ret = mbedtls_pk_verify_ext(pk_type, options, &pk,
                                digest, message_str->x, message_str->len,
                                result_str->x, sig_len);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (result == MBEDTLS_ERR_RSA_INVALID_PADDING) {
        /* Mbed TLS distinguishes "invalid padding" from "valid padding but
         * the rest of the signature is invalid". This has little use in
         * practice and PSA doesn't report this distinction.
         * In this case, PSA returns PSA_ERROR_INVALID_SIGNATURE translated
         * to MBEDTLS_ERR_RSA_VERIFY_FAILED.
         * However, currently `mbedtls_pk_verify_ext()` may use either the
         * PSA or the Mbed TLS API, depending on the PSS options used.
         * So, it may return either INVALID_PADDING or INVALID_SIGNATURE.
         */
        TEST_ASSERT(ret == result || ret == MBEDTLS_ERR_RSA_VERIFY_FAILED);
    } else
#endif
    {
        TEST_EQUAL(ret, result);
    }

exit:
    mbedtls_pk_free(&pk);
    MD_OR_USE_PSA_DONE();
}

void test_pk_rsa_verify_ext_test_vec_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_pk_rsa_verify_ext_test_vec( &data0, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, (char *) params[4], (char *) params[5], &data6, ((mbedtls_test_argument_t *) params[8])->sint, ((mbedtls_test_argument_t *) params[9])->sint, ((mbedtls_test_argument_t *) params[10])->sint, ((mbedtls_test_argument_t *) params[11])->sint, ((mbedtls_test_argument_t *) params[12])->sint );
}
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
#line 908 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_ec_test_vec(int type, int id, data_t *key, data_t *hash,
                    data_t *sig, int ret)
{
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(type)) == 0);

    TEST_ASSERT(mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA));
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    TEST_ASSERT(key->len <= MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN);
    memcpy(pk.pub_raw, key->x, key->len);
    pk.ec_family = mbedtls_ecc_group_to_psa(id, &(pk.ec_bits));
    pk.pub_raw_len = key->len;
#else
    mbedtls_ecp_keypair *eckey = (mbedtls_ecp_keypair *) mbedtls_pk_ec(pk);

    TEST_ASSERT(mbedtls_ecp_group_load(&eckey->grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_point_read_binary(&eckey->grp, &eckey->Q,
                                              key->x, key->len) == 0);
#endif

    // MBEDTLS_MD_NONE is used since it will be ignored.
    TEST_ASSERT(mbedtls_pk_verify(&pk, MBEDTLS_MD_NONE,
                                  hash->x, hash->len, sig->x, sig->len) == ret);

exit:
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_ec_test_vec_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_pk_ec_test_vec( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, &data2, &data4, &data6, ((mbedtls_test_argument_t *) params[8])->sint );
}
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_ECP_RESTARTABLE)
#if defined(MBEDTLS_ECDSA_C)
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#line 943 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_sign_verify_restart(int pk_type, int grp_id, char *d_str,
                            char *QX_str, char *QY_str,
                            int md_alg, data_t *hash, data_t *sig_check,
                            int max_ops, int min_restart, int max_restart)
{
    int ret, cnt_restart;
    mbedtls_pk_restart_ctx rs_ctx;
    mbedtls_pk_context prv, pub;
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t slen;

    mbedtls_pk_restart_init(&rs_ctx);
    mbedtls_pk_init(&prv);
    mbedtls_pk_init(&pub);
    USE_PSA_INIT();

    memset(sig, 0, sizeof(sig));

    TEST_ASSERT(mbedtls_pk_setup(&prv, mbedtls_pk_info_from_type(pk_type)) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&mbedtls_pk_ec_rw(prv)->grp, grp_id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&mbedtls_pk_ec_rw(prv)->d, d_str) == 0);

    TEST_ASSERT(mbedtls_pk_setup(&pub, mbedtls_pk_info_from_type(pk_type)) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&mbedtls_pk_ec_rw(pub)->grp, grp_id) == 0);
    TEST_ASSERT(mbedtls_ecp_point_read_string(&mbedtls_pk_ec_rw(pub)->Q, 16, QX_str, QY_str) == 0);

    mbedtls_ecp_set_max_ops(max_ops);

    slen = sizeof(sig);
    cnt_restart = 0;
    do {
        ret = mbedtls_pk_sign_restartable(&prv, md_alg, hash->x, hash->len,
                                          sig, sizeof(sig), &slen,
                                          mbedtls_test_rnd_std_rand, NULL,
                                          &rs_ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restart);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(slen == sig_check->len);
    TEST_ASSERT(memcmp(sig, sig_check->x, slen) == 0);

    TEST_ASSERT(cnt_restart >= min_restart);
    TEST_ASSERT(cnt_restart <= max_restart);

    cnt_restart = 0;
    do {
        ret = mbedtls_pk_verify_restartable(&pub, md_alg,
                                            hash->x, hash->len, sig, slen, &rs_ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restart);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(cnt_restart >= min_restart);
    TEST_ASSERT(cnt_restart <= max_restart);

    sig[0]++;
    do {
        ret = mbedtls_pk_verify_restartable(&pub, md_alg,
                                            hash->x, hash->len, sig, slen, &rs_ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    TEST_ASSERT(ret != 0);
    sig[0]--;

    /* Do we leak memory when aborting? try verify then sign
     * This test only makes sense when we actually restart */
    if (min_restart > 0) {
        ret = mbedtls_pk_verify_restartable(&pub, md_alg,
                                            hash->x, hash->len, sig, slen, &rs_ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
        mbedtls_pk_restart_free(&rs_ctx);

        slen = sizeof(sig);
        ret = mbedtls_pk_sign_restartable(&prv, md_alg, hash->x, hash->len,
                                          sig, sizeof(sig), &slen,
                                          mbedtls_test_rnd_std_rand, NULL,
                                          &rs_ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_pk_restart_free(&rs_ctx);
    mbedtls_pk_free(&prv);
    mbedtls_pk_free(&pub);
    USE_PSA_DONE();
}

void test_pk_sign_verify_restart_wrapper( void ** params )
{
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};
    data_t data8 = {(uint8_t *) params[8], ((mbedtls_test_argument_t *) params[9])->len};

    test_pk_sign_verify_restart( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, (char *) params[2], (char *) params[3], (char *) params[4], ((mbedtls_test_argument_t *) params[5])->sint, &data6, &data8, ((mbedtls_test_argument_t *) params[10])->sint, ((mbedtls_test_argument_t *) params[11])->sint, ((mbedtls_test_argument_t *) params[12])->sint );
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */
#endif /* MBEDTLS_ECDSA_C */
#endif /* MBEDTLS_ECP_RESTARTABLE */
#if defined(MBEDTLS_MD_CAN_SHA256)
#line 1030 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_sign_verify(int type, int curve_or_keybits, int sign_ret, int verify_ret)
{
    mbedtls_pk_context pk;
    size_t sig_len;
    unsigned char hash[32]; // Hard-coded for SHA256
    size_t hash_len = sizeof(hash);
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    void *rs_ctx = NULL;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_pk_restart_ctx ctx;

    rs_ctx = &ctx;
    mbedtls_pk_restart_init(rs_ctx);
    /* This value is large enough that the operation will complete in one run.
     * See comments at the top of ecp_test_vect_restart in
     * test_suite_ecp.function for estimates of operation counts. */
    mbedtls_ecp_set_max_ops(42000);
#endif

    mbedtls_pk_init(&pk);
    MD_OR_USE_PSA_INIT();

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(type)) == 0);
    TEST_ASSERT(pk_genkey(&pk, curve_or_keybits) == 0);

    TEST_ASSERT(mbedtls_pk_sign_restartable(&pk, MBEDTLS_MD_SHA256,
                                            hash, hash_len,
                                            sig, sizeof(sig), &sig_len,
                                            mbedtls_test_rnd_std_rand, NULL,
                                            rs_ctx) == sign_ret);
    if (sign_ret == 0) {
        TEST_ASSERT(sig_len <= MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    } else {
        sig_len = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
    }

    TEST_ASSERT(mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                  hash, hash_len, sig, sig_len) == verify_ret);

    if (verify_ret == 0) {
        hash[0]++;
        TEST_ASSERT(mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                      hash, hash_len, sig, sig_len) != 0);
        hash[0]--;

        sig[0]++;
        TEST_ASSERT(mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                      hash, hash_len, sig, sig_len) != 0);
        sig[0]--;
    }

    TEST_ASSERT(mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, hash_len,
                                sig, sizeof(sig), &sig_len,
                                mbedtls_test_rnd_std_rand,
                                NULL) == sign_ret);
    if (sign_ret == 0) {
        TEST_ASSERT(sig_len <= MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    } else {
        sig_len = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
    }

    TEST_ASSERT(mbedtls_pk_verify_restartable(&pk, MBEDTLS_MD_SHA256,
                                              hash, hash_len, sig, sig_len, rs_ctx) == verify_ret);

    if (verify_ret == 0) {
        hash[0]++;
        TEST_ASSERT(mbedtls_pk_verify_restartable(&pk, MBEDTLS_MD_SHA256,
                                                  hash, sizeof(hash), sig, sig_len, rs_ctx) != 0);
        hash[0]--;

        sig[0]++;
        TEST_ASSERT(mbedtls_pk_verify_restartable(&pk, MBEDTLS_MD_SHA256,
                                                  hash, sizeof(hash), sig, sig_len, rs_ctx) != 0);
        sig[0]--;
    }

exit:
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_pk_restart_free(rs_ctx);
#endif
    mbedtls_pk_free(&pk);
    MD_OR_USE_PSA_DONE();
}

void test_pk_sign_verify_wrapper( void ** params )
{

    test_pk_sign_verify( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_MD_CAN_SHA256 */
#if defined(MBEDTLS_RSA_C)
#line 1119 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_encrypt_decrypt_test(data_t *message, int mod,
                                 char *input_P, char *input_Q,
                                 char *input_N, char *input_E,
                                 int ret)
{
    unsigned char output[300], result[300];
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    size_t olen, rlen;

    mbedtls_pk_init(&pk);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    USE_PSA_INIT();

    memset(&rnd_info,  0, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(output,     0, sizeof(output));

    /* encryption test */

    /* init pk-rsa context */
    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    rsa = mbedtls_pk_rsa(pk);

    /* load public key */
    rsa->len = mod / 8;
    TEST_ASSERT(mbedtls_test_read_mpi(&rsa->N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&rsa->E, input_E) == 0);

    TEST_ASSERT(mbedtls_pk_encrypt(&pk, message->x, message->len,
                                   output, &olen, sizeof(output),
                                   mbedtls_test_rnd_pseudo_rand, &rnd_info) == ret);

    /* decryption test */
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);

    /* init pk-rsa context */
    mbedtls_pk_free(&pk);
    TEST_ASSERT(mbedtls_pk_setup(&pk,
                                 mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    rsa = mbedtls_pk_rsa(pk);

    /* load public key */
    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    /* load private key */
    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_rsa_import(rsa, &N, &P, &Q, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(rsa) == (size_t) (mod / 8));
    TEST_ASSERT(mbedtls_rsa_complete(rsa) == 0);

    memset(result, 0, sizeof(result));
    rlen = 0;
    TEST_ASSERT(mbedtls_pk_decrypt(&pk, output, olen,
                                   result, &rlen, sizeof(result),
                                   mbedtls_test_rnd_pseudo_rand, &rnd_info) == ret);
    if (ret == 0) {
        TEST_ASSERT(rlen == message->len);
        TEST_ASSERT(memcmp(result, message->x, rlen) == 0);
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_rsa_encrypt_decrypt_test_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_pk_rsa_encrypt_decrypt_test( &data0, ((mbedtls_test_argument_t *) params[2])->sint, (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], ((mbedtls_test_argument_t *) params[7])->sint );
}
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_RSA_C)
#line 1194 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_decrypt_test_vec(data_t *cipher, int mod,
                             char *input_P, char *input_Q,
                             char *input_N, char *input_E,
                             data_t *clear, int ret)
{
    unsigned char output[256];
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    size_t olen;

    mbedtls_pk_init(&pk);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    USE_PSA_INIT();

    memset(&rnd_info,  0, sizeof(mbedtls_test_rnd_pseudo_info));

    /* init pk-rsa context */
    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    rsa = mbedtls_pk_rsa(pk);

    /* load public key */
    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    /* load private key */
    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_rsa_import(rsa, &N, &P, &Q, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(rsa) == (size_t) (mod / 8));
    TEST_ASSERT(mbedtls_rsa_complete(rsa) == 0);

    /* decryption test */
    memset(output, 0, sizeof(output));
    olen = 0;
    TEST_ASSERT(mbedtls_pk_decrypt(&pk, cipher->x, cipher->len,
                                   output, &olen, sizeof(output),
                                   mbedtls_test_rnd_pseudo_rand, &rnd_info) == ret);
    if (ret == 0) {
        TEST_ASSERT(olen == clear->len);
        TEST_ASSERT(memcmp(output, clear->x, olen) == 0);
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_rsa_decrypt_test_vec_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};

    test_pk_rsa_decrypt_test_vec( &data0, ((mbedtls_test_argument_t *) params[2])->sint, (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], &data7, ((mbedtls_test_argument_t *) params[9])->sint );
}
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#line 1248 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_wrap_rsa_decrypt_test_vec(data_t *cipher, int mod,
                                  char *input_P, char *input_Q,
                                  char *input_N, char *input_E,
                                  data_t *clear, int ret)
{
    unsigned char output[256];
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    mbedtls_svc_key_id_t key_id;
    size_t olen;

    mbedtls_pk_init(&pk);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    USE_PSA_INIT();

    memset(&rnd_info,  0, sizeof(mbedtls_test_rnd_pseudo_info));

    /* init pk-rsa context */
    TEST_EQUAL(mbedtls_pk_setup(&pk,
                                mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)), 0);
    rsa = mbedtls_pk_rsa(pk);

    /* load public key */
    TEST_EQUAL(mbedtls_test_read_mpi(&N, input_N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&E, input_E), 0);

    /* load private key */
    TEST_EQUAL(mbedtls_test_read_mpi(&P, input_P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&Q, input_Q), 0);
    TEST_EQUAL(mbedtls_rsa_import(rsa, &N, &P, &Q, NULL, &E), 0);
    TEST_EQUAL(mbedtls_rsa_get_len(rsa), (size_t) (mod / 8));
    TEST_EQUAL(mbedtls_rsa_complete(rsa), 0);

    /* Turn PK context into an opaque one. */
    TEST_EQUAL(mbedtls_pk_wrap_as_opaque(&pk, &key_id,
                                         PSA_ALG_RSA_PKCS1V15_CRYPT,
                                         PSA_KEY_USAGE_DECRYPT,
                                         PSA_ALG_NONE), 0);

    /* decryption test */
    memset(output, 0, sizeof(output));
    olen = 0;
    TEST_EQUAL(mbedtls_pk_decrypt(&pk, cipher->x, cipher->len,
                                  output, &olen, sizeof(output),
                                  mbedtls_test_rnd_pseudo_rand, &rnd_info), ret);
    if (ret == 0) {
        TEST_EQUAL(olen, clear->len);
        TEST_EQUAL(memcmp(output, clear->x, olen), 0);
    }

    TEST_EQUAL(PSA_SUCCESS, psa_destroy_key(key_id));

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_wrap_rsa_decrypt_test_vec_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};

    test_pk_wrap_rsa_decrypt_test_vec( &data0, ((mbedtls_test_argument_t *) params[2])->sint, (char *) params[3], (char *) params[4], (char *) params[5], (char *) params[6], &data7, ((mbedtls_test_argument_t *) params[9])->sint );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_RSA_C */
#line 1312 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_ec_nocrypt(int type)
{
    mbedtls_pk_context pk;
    unsigned char output[100];
    unsigned char input[100];
    mbedtls_test_rnd_pseudo_info rnd_info;
    size_t olen = 0;
    int ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    memset(&rnd_info,  0, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(output,     0, sizeof(output));
    memset(input,      0, sizeof(input));

    TEST_ASSERT(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(type)) == 0);

    TEST_ASSERT(mbedtls_pk_encrypt(&pk, input, sizeof(input),
                                   output, &olen, sizeof(output),
                                   mbedtls_test_rnd_pseudo_rand, &rnd_info) == ret);

    TEST_ASSERT(mbedtls_pk_decrypt(&pk, input, sizeof(input),
                                   output, &olen, sizeof(output),
                                   mbedtls_test_rnd_pseudo_rand, &rnd_info) == ret);

exit:
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_ec_nocrypt_wrapper( void ** params )
{

    test_pk_ec_nocrypt( ((mbedtls_test_argument_t *) params[0])->sint );
}
#if defined(MBEDTLS_RSA_C)
#line 1345 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_overflow(void)
{
    mbedtls_pk_context pk;
    size_t hash_len = UINT_MAX + 1, sig_len = UINT_MAX + 1;
    unsigned char hash[50], sig[100];

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    TEST_EQUAL(mbedtls_pk_setup(&pk,
                                mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)), 0);

#if defined(MBEDTLS_PKCS1_V21)
    TEST_EQUAL(mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, NULL, &pk,
                                     MBEDTLS_MD_NONE, hash, hash_len, sig, sig_len),
               MBEDTLS_ERR_PK_BAD_INPUT_DATA);
#endif /* MBEDTLS_PKCS1_V21 */

    TEST_EQUAL(mbedtls_pk_verify(&pk, MBEDTLS_MD_NONE, hash, hash_len,
                                 sig, sig_len),
               MBEDTLS_ERR_PK_BAD_INPUT_DATA);

#if defined(MBEDTLS_PKCS1_V21)
    TEST_EQUAL(mbedtls_pk_sign_ext(MBEDTLS_PK_RSASSA_PSS, &pk,
                                   MBEDTLS_MD_NONE, hash, hash_len,
                                   sig, sizeof(sig), &sig_len,
                                   mbedtls_test_rnd_std_rand, NULL),
               MBEDTLS_ERR_PK_BAD_INPUT_DATA);
#endif /* MBEDTLS_PKCS1_V21 */

    TEST_EQUAL(mbedtls_pk_sign(&pk, MBEDTLS_MD_NONE, hash, hash_len,
                               sig, sizeof(sig), &sig_len,
                               mbedtls_test_rnd_std_rand, NULL),
               MBEDTLS_ERR_PK_BAD_INPUT_DATA);

exit:
    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_rsa_overflow_wrapper( void ** params )
{
    (void)params;

    test_pk_rsa_overflow(  );
}
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
#line 1390 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_alt(void)
{
    /*
     * An rsa_alt context can only do private operations (decrypt, sign).
     * Test it against the public operations (encrypt, verify) of a
     * corresponding rsa context.
     */
    mbedtls_rsa_context raw;
    mbedtls_pk_context rsa, alt;
    mbedtls_pk_debug_item dbg_items[10];
    unsigned char hash[50], sig[RSA_KEY_LEN];
    unsigned char msg[50], ciph[RSA_KEY_LEN], test[50];
    size_t sig_len, ciph_len, test_len;
    int ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

    mbedtls_rsa_init(&raw);
    mbedtls_pk_init(&rsa);
    mbedtls_pk_init(&alt);
    USE_PSA_INIT();

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));
    memset(msg, 0x2a, sizeof(msg));
    memset(ciph, 0, sizeof(ciph));
    memset(test, 0, sizeof(test));

    /* Initialize PK RSA context with random key */
    TEST_ASSERT(mbedtls_pk_setup(&rsa,
                                 mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
    TEST_ASSERT(pk_genkey(&rsa, RSA_KEY_SIZE) == 0);

    /* Extract key to the raw rsa context */
    TEST_ASSERT(mbedtls_rsa_copy(&raw, mbedtls_pk_rsa(rsa)) == 0);

    /* Initialize PK RSA_ALT context */
    TEST_ASSERT(mbedtls_pk_setup_rsa_alt(&alt, (void *) &raw,
                                         mbedtls_rsa_decrypt_func, mbedtls_rsa_sign_func,
                                         mbedtls_rsa_key_len_func) == 0);

    /* Test administrative functions */
    TEST_ASSERT(mbedtls_pk_can_do(&alt, MBEDTLS_PK_RSA));
    TEST_ASSERT(mbedtls_pk_get_bitlen(&alt) == RSA_KEY_SIZE);
    TEST_ASSERT(mbedtls_pk_get_len(&alt) == RSA_KEY_LEN);
    TEST_ASSERT(mbedtls_pk_get_type(&alt) == MBEDTLS_PK_RSA_ALT);
    TEST_ASSERT(strcmp(mbedtls_pk_get_name(&alt), "RSA-alt") == 0);

#if defined(MBEDTLS_PSA_CRYPTO_C)
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    TEST_EQUAL(mbedtls_pk_get_psa_attributes(&alt,
                                             PSA_KEY_USAGE_ENCRYPT,
                                             &attributes),
               MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);
#endif /* MBEDTLS_PSA_CRYPTO_C */

    /* Test signature */
#if SIZE_MAX > UINT_MAX
    TEST_ASSERT(mbedtls_pk_sign(&alt, MBEDTLS_MD_NONE, hash, SIZE_MAX,
                                sig, sizeof(sig), &sig_len,
                                mbedtls_test_rnd_std_rand, NULL)
                == MBEDTLS_ERR_PK_BAD_INPUT_DATA);
#endif /* SIZE_MAX > UINT_MAX */
    TEST_ASSERT(mbedtls_pk_sign(&alt, MBEDTLS_MD_NONE, hash, sizeof(hash),
                                sig, sizeof(sig), &sig_len,
                                mbedtls_test_rnd_std_rand, NULL)
                == 0);
    TEST_ASSERT(sig_len == RSA_KEY_LEN);
    TEST_ASSERT(mbedtls_pk_verify(&rsa, MBEDTLS_MD_NONE,
                                  hash, sizeof(hash), sig, sig_len) == 0);

    /* Test decrypt */
    TEST_ASSERT(mbedtls_pk_encrypt(&rsa, msg, sizeof(msg),
                                   ciph, &ciph_len, sizeof(ciph),
                                   mbedtls_test_rnd_std_rand, NULL) == 0);
    TEST_ASSERT(mbedtls_pk_decrypt(&alt, ciph, ciph_len,
                                   test, &test_len, sizeof(test),
                                   mbedtls_test_rnd_std_rand, NULL) == 0);
    TEST_ASSERT(test_len == sizeof(msg));
    TEST_ASSERT(memcmp(test, msg, test_len) == 0);

    /* Test forbidden operations */
    TEST_ASSERT(mbedtls_pk_encrypt(&alt, msg, sizeof(msg),
                                   ciph, &ciph_len, sizeof(ciph),
                                   mbedtls_test_rnd_std_rand, NULL) == ret);
    TEST_ASSERT(mbedtls_pk_verify(&alt, MBEDTLS_MD_NONE,
                                  hash, sizeof(hash), sig, sig_len) == ret);
    TEST_ASSERT(mbedtls_pk_debug(&alt, dbg_items) == ret);

exit:
    mbedtls_rsa_free(&raw);
    mbedtls_pk_free(&rsa); mbedtls_pk_free(&alt);
    USE_PSA_DONE();
}

void test_pk_rsa_alt_wrapper( void ** params )
{
    (void)params;

    test_pk_rsa_alt(  );
}
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_TEST_PK_PSA_SIGN)
#line 1485 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_psa_sign(int curve_or_keybits, int psa_type, int expected_bits)
{
    mbedtls_pk_context pk;
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    unsigned char pkey_legacy[200];
    unsigned char pkey_psa[200];
    unsigned char *pkey_legacy_start, *pkey_psa_start;
    psa_algorithm_t alg_psa;
    size_t sig_len, klen_legacy, klen_psa;
    int ret;
    mbedtls_svc_key_id_t key_id;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    /*
     * This tests making signatures with a wrapped PSA key:
     * - generate a fresh ECP/RSA legacy PK context
     * - wrap it in a PK context and make a signature this way
     * - extract the public key
     * - parse it to a PK context and verify the signature this way
     */

    mbedtls_pk_init(&pk);
    USE_PSA_INIT();

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if (PSA_KEY_TYPE_IS_RSA(psa_type)) {
        /* Create legacy RSA public/private key in PK context. */
        TEST_ASSERT(mbedtls_pk_setup(&pk,
                                     mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0);
        TEST_ASSERT(mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk),
                                        mbedtls_test_rnd_std_rand, NULL,
                                        curve_or_keybits, 3) == 0);
        alg_psa = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    } else
#endif /* MBEDTLS_RSA_C && MBEDTLS_GENPRIME */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_type)) {
        mbedtls_ecp_group_id grpid = curve_or_keybits;

        /* Create legacy EC public/private key in PK context. */
        TEST_ASSERT(mbedtls_pk_setup(&pk,
                                     mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0);
        TEST_ASSERT(pk_genkey(&pk, grpid) == 0);

        alg_psa = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    } else
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    {
        (void) curve_or_keybits;
        TEST_ASSUME(!"Opaque PK key not supported in this configuration");
    }

    /* Export underlying public key for re-importing in a legacy context. */
#if defined(MBEDTLS_PK_WRITE_C)
    ret = mbedtls_pk_write_pubkey_der(&pk, pkey_legacy,
                                      sizeof(pkey_legacy));
    TEST_ASSERT(ret >= 0);
    klen_legacy = (size_t) ret;
    /* mbedtls_pk_write_pubkey_der() writes backwards in the data buffer. */
    pkey_legacy_start = pkey_legacy + sizeof(pkey_legacy) - klen_legacy;
#else
    ret = mbedtls_ecp_point_write_binary(&(mbedtls_pk_ec_ro(pk)->grp),
                                         &(mbedtls_pk_ec_ro(pk)->Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &klen_legacy, pkey_legacy,
                                         sizeof(pkey_legacy));
    TEST_EQUAL(ret, 0);
    pkey_legacy_start = pkey_legacy;
#endif /* MBEDTLS_PK_WRITE_C */

    /* Turn PK context into an opaque one. */
    TEST_ASSERT(mbedtls_pk_wrap_as_opaque(&pk, &key_id, alg_psa,
                                          PSA_KEY_USAGE_SIGN_HASH,
                                          PSA_ALG_NONE) == 0);

    PSA_ASSERT(psa_get_key_attributes(key_id, &attributes));
    TEST_EQUAL(psa_get_key_type(&attributes), (psa_key_type_t) psa_type);
    TEST_EQUAL(psa_get_key_bits(&attributes), (size_t) expected_bits);
    TEST_EQUAL(psa_get_key_lifetime(&attributes),
               PSA_KEY_LIFETIME_VOLATILE);

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    TEST_ASSERT(mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                                hash, sizeof(hash), sig, sizeof(sig), &sig_len,
                                NULL, NULL) == 0);
    /* Only opaque EC keys support verification. */
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_type)) {
        TEST_ASSERT(mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                      hash, sizeof(hash), sig, sig_len) == 0);
    }

    /* Export underlying public key for re-importing in a psa context. */
#if defined(MBEDTLS_PK_WRITE_C)
    ret = mbedtls_pk_write_pubkey_der(&pk, pkey_psa,
                                      sizeof(pkey_psa));
    TEST_ASSERT(ret >= 0);
    klen_psa = (size_t) ret;
    /* mbedtls_pk_write_pubkey_der() writes backwards in the data buffer. */
    pkey_psa_start = pkey_psa + sizeof(pkey_psa) - klen_psa;
#else
    psa_status_t status;

    status = psa_export_public_key(key_id, pkey_psa, sizeof(pkey_psa),
                                   &klen_psa);
    TEST_EQUAL(status, PSA_SUCCESS);
    pkey_psa_start = pkey_psa;
#endif /* MBEDTLS_PK_WRITE_C */

    TEST_ASSERT(klen_psa == klen_legacy);
    TEST_ASSERT(memcmp(pkey_psa_start, pkey_legacy_start, klen_psa) == 0);

    mbedtls_pk_free(&pk);
    TEST_ASSERT(PSA_SUCCESS == psa_destroy_key(key_id));

    mbedtls_pk_init(&pk);

    /* If we used "pk_write" previously, then we go for a "pk_parse" here;
     * otherwise if we went for "ecp_point_write_binary" then we'll go
     * for a "ecp_point_read_binary" here. This allows to drop dependencies
     * on "PK_WRITE" and "PK_PARSE" if required */
#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_PK_PARSE_C)
    TEST_EQUAL(mbedtls_pk_parse_public_key(&pk, pkey_legacy_start,
                                           klen_legacy), 0);
#else
    TEST_EQUAL(mbedtls_pk_setup(&pk,
                                mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), 0);
    TEST_EQUAL(mbedtls_ecp_group_load(
                   &(mbedtls_pk_ec_rw(pk)->grp),
                   (mbedtls_ecp_group_id) curve_or_keybits), 0);
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&(mbedtls_pk_ec_ro(pk)->grp),
                                             &(mbedtls_pk_ec_rw(pk)->Q),
                                             pkey_legacy_start, klen_legacy), 0);
#endif
    TEST_ASSERT(mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                                  hash, sizeof(hash), sig, sig_len) == 0);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    mbedtls_pk_free(&pk);
    USE_PSA_DONE();
}

void test_pk_psa_sign_wrapper( void ** params )
{

    test_pk_psa_sign( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_TEST_PK_PSA_SIGN */
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_MD_CAN_SHA256 */
#if defined(MBEDTLS_GENPRIME)
#line 1637 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_sign_ext(int pk_type, int curve_or_keybits, int key_pk_type, int md_alg)
{
    mbedtls_pk_context pk;
    size_t sig_len;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t hash_len = mbedtls_md_get_size_from_type(md_alg);
    void const *options = NULL;
    mbedtls_pk_rsassa_pss_options rsassa_pss_options;
    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    mbedtls_pk_init(&pk);
    MD_OR_USE_PSA_INIT();

    TEST_EQUAL(mbedtls_pk_setup(&pk,
                                mbedtls_pk_info_from_type(pk_type)), 0);
    TEST_EQUAL(pk_genkey(&pk, curve_or_keybits), 0);

    TEST_EQUAL(mbedtls_pk_sign_ext(key_pk_type, &pk, md_alg, hash, hash_len,
                                   sig, sizeof(sig), &sig_len,
                                   mbedtls_test_rnd_std_rand, NULL), 0);

    if (key_pk_type == MBEDTLS_PK_RSASSA_PSS) {
        rsassa_pss_options.mgf1_hash_id = md_alg;
        TEST_ASSERT(hash_len != 0);
        rsassa_pss_options.expected_salt_len = hash_len;
        options = (const void *) &rsassa_pss_options;
    }
    TEST_EQUAL(mbedtls_pk_verify_ext(key_pk_type, options, &pk, md_alg,
                                     hash, hash_len, sig, sig_len), 0);
exit:
    mbedtls_pk_free(&pk);
    MD_OR_USE_PSA_DONE();
}

void test_pk_sign_ext_wrapper( void ** params )
{

    test_pk_sign_ext( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_GENPRIME */
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_GENPRIME)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#line 1675 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_psa_wrap_sign_ext(int pk_type, int key_bits, int key_pk_type, int md_alg)
{
    mbedtls_pk_context pk;
    size_t sig_len, pkey_len;
    mbedtls_svc_key_id_t key_id;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    unsigned char pkey[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    unsigned char *pkey_start;
    unsigned char hash[PSA_HASH_MAX_SIZE];
    psa_algorithm_t psa_md_alg = mbedtls_md_psa_alg_from_type(md_alg);
    psa_algorithm_t psa_alg;
    size_t hash_len = PSA_HASH_LENGTH(psa_md_alg);
    void const *options = NULL;
    mbedtls_pk_rsassa_pss_options rsassa_pss_options;
    int ret;

    mbedtls_pk_init(&pk);
    PSA_INIT();

    /* Create legacy RSA public/private key in PK context. */
    mbedtls_pk_init(&pk);
    TEST_EQUAL(mbedtls_pk_setup(&pk,
                                mbedtls_pk_info_from_type(pk_type)), 0);
    TEST_EQUAL(mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk),
                                   mbedtls_test_rnd_std_rand, NULL,
                                   key_bits, 3), 0);

    /* Export underlying public key for re-importing in a legacy context. */
    ret = mbedtls_pk_write_pubkey_der(&pk, pkey, sizeof(pkey));
    TEST_ASSERT(ret >= 0);

    pkey_len = (size_t) ret;
    /* mbedtls_pk_write_pubkey_der() writes backwards in the data buffer. */
    pkey_start = pkey + sizeof(pkey) - pkey_len;

    if (key_pk_type == MBEDTLS_PK_RSA) {
        psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(psa_md_alg);
    } else if (key_pk_type == MBEDTLS_PK_RSASSA_PSS) {
        psa_alg = PSA_ALG_RSA_PSS(psa_md_alg);
    } else {
        TEST_ASSUME(!"PK key type not supported in this configuration");
    }

    /* Turn PK context into an opaque one. */
    TEST_EQUAL(mbedtls_pk_wrap_as_opaque(&pk, &key_id, psa_alg,
                                         PSA_KEY_USAGE_SIGN_HASH,
                                         PSA_ALG_NONE), 0);

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    TEST_EQUAL(mbedtls_pk_sign_ext(key_pk_type, &pk, md_alg, hash, hash_len,
                                   sig, sizeof(sig), &sig_len,
                                   mbedtls_test_rnd_std_rand, NULL), 0);

    mbedtls_pk_free(&pk);
    TEST_EQUAL(PSA_SUCCESS, psa_destroy_key(key_id));

    mbedtls_pk_init(&pk);
    TEST_EQUAL(mbedtls_pk_parse_public_key(&pk, pkey_start, pkey_len), 0);

    if (key_pk_type == MBEDTLS_PK_RSASSA_PSS) {
        rsassa_pss_options.mgf1_hash_id = md_alg;
        TEST_ASSERT(hash_len != 0);
        rsassa_pss_options.expected_salt_len = hash_len;
        options = (const void *) &rsassa_pss_options;
    }
    TEST_EQUAL(mbedtls_pk_verify_ext(key_pk_type, options, &pk, md_alg,
                                     hash, hash_len, sig, sig_len), 0);

exit:
    mbedtls_pk_free(&pk);
    PSA_DONE();
}

void test_pk_psa_wrap_sign_ext_wrapper( void ** params )
{

    test_pk_psa_wrap_sign_ext( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_GENPRIME */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_PSA_CRYPTO_C)
#line 1752 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_get_psa_attributes(int pk_type, int from_pair,
                           int usage_arg,
                           int to_pair, int expected_alg)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t usage = usage_arg;

    PSA_INIT();

    psa_key_type_t expected_psa_type = 0;
    TEST_EQUAL(pk_setup_for_type(pk_type, from_pair,
                                 &pk, &expected_psa_type), 0);
    if (!to_pair) {
        expected_psa_type = PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(expected_psa_type);
    }

    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_VOLATILE; //TODO: diversity
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT; //TODO: diversity
    psa_set_key_id(&attributes, key_id);
    psa_set_key_lifetime(&attributes, lifetime);
    psa_set_key_enrollment_algorithm(&attributes, 42);
    psa_key_usage_t expected_usage = pk_get_psa_attributes_implied_usage(usage);

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    /* When the resulting algorithm is ECDSA, the compile-time configuration
     * can cause it to be either deterministic or randomized ECDSA.
     * Rather than have two near-identical sets of test data depending on
     * the configuration, always use randomized in the test data and
     * tweak the expected result here. */
    if (expected_alg == PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)) {
        expected_alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_ANY_HASH);
    }
#endif

    TEST_EQUAL(mbedtls_pk_get_psa_attributes(&pk, usage, &attributes), 0);

    TEST_EQUAL(psa_get_key_lifetime(&attributes), lifetime);
    TEST_ASSERT(mbedtls_svc_key_id_equal(psa_get_key_id(&attributes),
                                         key_id));
    TEST_EQUAL(psa_get_key_type(&attributes), expected_psa_type);
    TEST_EQUAL(psa_get_key_bits(&attributes),
               mbedtls_pk_get_bitlen(&pk));
    TEST_EQUAL(psa_get_key_usage_flags(&attributes), expected_usage);
    TEST_EQUAL(psa_get_key_algorithm(&attributes), expected_alg);
    TEST_EQUAL(psa_get_key_enrollment_algorithm(&attributes), PSA_ALG_NONE);

exit:
    mbedtls_pk_free(&pk);
    psa_reset_key_attributes(&attributes);
    PSA_DONE();
}

void test_pk_get_psa_attributes_wrapper( void ** params )
{

    test_pk_get_psa_attributes( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
#if defined(MBEDTLS_PSA_CRYPTO_C)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_PKCS1_V21)
#if defined(MBEDTLS_GENPRIME)
#line 1808 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_rsa_v21_get_psa_attributes(int md_type, int from_pair,
                                   int usage_arg,
                                   int to_pair, int expected_alg)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    psa_key_usage_t usage = usage_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_INIT();

    psa_key_type_t expected_psa_type = 0;
    TEST_EQUAL(pk_setup_for_type(MBEDTLS_PK_RSA, from_pair,
                                 &pk, &expected_psa_type), 0);
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    TEST_EQUAL(mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, md_type), 0);
    if (!to_pair) {
        expected_psa_type = PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(expected_psa_type);
    }
    psa_key_usage_t expected_usage = pk_get_psa_attributes_implied_usage(usage);

    TEST_EQUAL(mbedtls_pk_get_psa_attributes(&pk, usage, &attributes), 0);

    TEST_EQUAL(psa_get_key_lifetime(&attributes), PSA_KEY_LIFETIME_VOLATILE);
    TEST_ASSERT(mbedtls_svc_key_id_equal(psa_get_key_id(&attributes),
                                         MBEDTLS_SVC_KEY_ID_INIT));
    TEST_EQUAL(psa_get_key_type(&attributes), expected_psa_type);
    TEST_EQUAL(psa_get_key_bits(&attributes),
               mbedtls_pk_get_bitlen(&pk));
    TEST_EQUAL(psa_get_key_usage_flags(&attributes), expected_usage);
    TEST_EQUAL(psa_get_key_algorithm(&attributes), expected_alg);
    TEST_EQUAL(psa_get_key_enrollment_algorithm(&attributes), PSA_ALG_NONE);

exit:
    mbedtls_pk_free(&pk);
    psa_reset_key_attributes(&attributes);
    PSA_DONE();
}

void test_pk_rsa_v21_get_psa_attributes_wrapper( void ** params )
{

    test_pk_rsa_v21_get_psa_attributes( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint );
}
#endif /* MBEDTLS_GENPRIME */
#endif /* MBEDTLS_PKCS1_V21 */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PSA_CRYPTO_C */
#if defined(MBEDTLS_PSA_CRYPTO_C)
#line 1849 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_get_psa_attributes_fail(int pk_type, int from_pair,
                                int usage_arg,
                                int expected_ret)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t usage = usage_arg;

    PSA_INIT();

    psa_key_type_t expected_psa_type;
    TEST_EQUAL(pk_setup_for_type(pk_type, from_pair,
                                 &pk, &expected_psa_type), 0);

    TEST_EQUAL(mbedtls_pk_get_psa_attributes(&pk, usage, &attributes),
               expected_ret);

exit:
    mbedtls_pk_free(&pk);
    psa_reset_key_attributes(&attributes);
    PSA_DONE();
}

void test_pk_get_psa_attributes_fail_wrapper( void ** params )
{

    test_pk_get_psa_attributes_fail( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#line 1875 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_pk.function"
void test_pk_get_psa_attributes_opaque(int from_type_arg, int from_bits_arg,
                                  int from_usage_arg, int from_alg_arg,
                                  int usage_arg,
                                  int expected_ret,
                                  int to_pair, int expected_usage_arg)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t from_type = from_type_arg;
    size_t bits = from_bits_arg;
    psa_key_usage_t from_usage = from_usage_arg;
    psa_algorithm_t alg = from_alg_arg;
    psa_key_usage_t usage = usage_arg;
    psa_key_usage_t expected_usage = expected_usage_arg;

    PSA_INIT();

    psa_set_key_type(&attributes, from_type);
    psa_set_key_bits(&attributes, bits);
    psa_set_key_usage_flags(&attributes, from_usage);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_enrollment_algorithm(&attributes, 42);
    //TODO: test with persistent key
    PSA_ASSERT(psa_generate_key(&attributes, &key_id));
    TEST_EQUAL(mbedtls_pk_setup_opaque(&pk, key_id), 0);

    psa_key_type_t expected_psa_type =
        to_pair ? from_type : PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(from_type);

    TEST_EQUAL(mbedtls_pk_get_psa_attributes(&pk, usage, &attributes),
               expected_ret);

    if (expected_ret == 0) {
        TEST_EQUAL(psa_get_key_lifetime(&attributes), PSA_KEY_LIFETIME_VOLATILE);
        TEST_ASSERT(mbedtls_svc_key_id_equal(psa_get_key_id(&attributes),
                                             MBEDTLS_SVC_KEY_ID_INIT));
        TEST_EQUAL(psa_get_key_type(&attributes), expected_psa_type);
        TEST_EQUAL(psa_get_key_bits(&attributes), bits);
        TEST_EQUAL(psa_get_key_usage_flags(&attributes), expected_usage);
        TEST_EQUAL(psa_get_key_algorithm(&attributes), alg);
        TEST_EQUAL(psa_get_key_enrollment_algorithm(&attributes), PSA_ALG_NONE);
    }

exit:
    mbedtls_pk_free(&pk);
    psa_destroy_key(key_id);
    psa_reset_key_attributes(&attributes);
    PSA_DONE();
}

void test_pk_get_psa_attributes_opaque_wrapper( void ** params )
{

    test_pk_get_psa_attributes_opaque( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_C */


#line 54 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression(int32_t exp_id, intmax_t *out_value)
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch (exp_id) {
    
#if defined(MBEDTLS_PK_C)

        case 0:
            {
                *out_value = MBEDTLS_PK_RSA;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_RSA_GEN_KEY_MIN_BITS;
            }
            break;
        case 2:
            {
                *out_value = (MBEDTLS_RSA_GEN_KEY_MIN_BITS /8);
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_PK_ECKEY;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192R1;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_PK_ECKEY_DH;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_ECP_DP_CURVE25519;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_ECP_DP_CURVE448;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_PK_ECDSA;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256R1;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_ECP_DP_SECP384R1;
            }
            break;
        case 11:
            {
                *out_value = MBEDTLS_ECP_DP_SECP521R1;
            }
            break;
        case 12:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            }
            break;
        case 13:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH;
            }
            break;
        case 14:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
            }
            break;
        case 15:
            {
                *out_value = PSA_ALG_NONE;
            }
            break;
        case 16:
            {
                *out_value = PSA_ALG_STREAM_CIPHER;
            }
            break;
        case 17:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
            }
            break;
        case 18:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_CRYPT;
            }
            break;
        case 19:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
            }
            break;
        case 20:
            {
                *out_value = PSA_ALG_ECDH;
            }
            break;
        case 21:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            }
            break;
        case 22:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_1);
            }
            break;
        case 23:
            {
                *out_value = PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 24:
            {
                *out_value = PSA_KEY_USAGE_DERIVE|PSA_KEY_USAGE_SIGN_HASH;
            }
            break;
        case 25:
            {
                *out_value = PSA_KEY_TYPE_RSA_KEY_PAIR;
            }
            break;
        case 26:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
            }
            break;
        case 27:
            {
                *out_value = PSA_KEY_USAGE_COPY;
            }
            break;
        case 28:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_1);
            }
            break;
        case 29:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
            }
            break;
        case 30:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_SHA_1);
            }
            break;
        case 31:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN_RAW;
            }
            break;
        case 32:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT|PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 33:
            {
                *out_value = PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 34:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT|PSA_KEY_USAGE_DECRYPT|PSA_KEY_USAGE_SIGN_HASH;
            }
            break;
        case 35:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT;
            }
            break;
        case 36:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 37:
            {
                *out_value = MBEDTLS_ERR_RSA_VERIFY_FAILED;
            }
            break;
        case 38:
            {
                *out_value = MBEDTLS_ERR_ECP_VERIFY_FAILED;
            }
            break;
        case 39:
            {
                *out_value = MBEDTLS_ECP_DP_BP256R1;
            }
            break;
        case 40:
            {
                *out_value = MBEDTLS_ECP_DP_BP512R1;
            }
            break;
        case 41:
            {
                *out_value = MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            break;
        case 42:
            {
                *out_value = MBEDTLS_ERR_RSA_INVALID_PADDING;
            }
            break;
        case 43:
            {
                *out_value = MBEDTLS_MD_SHA256;
            }
            break;
        case 44:
            {
                *out_value = MBEDTLS_PK_RSASSA_PSS;
            }
            break;
        case 45:
            {
                *out_value = MBEDTLS_RSA_SALT_LEN_ANY;
            }
            break;
        case 46:
            {
                *out_value = MBEDTLS_MD_NONE;
            }
            break;
        case 47:
            {
                *out_value = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            }
            break;
        case 48:
            {
                *out_value = MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
            }
            break;
        case 49:
            {
                *out_value = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            break;
        case 50:
            {
                *out_value = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            }
            break;
        case 51:
            {
                *out_value = MBEDTLS_ECP_DP_SECP192K1;
            }
            break;
        case 52:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1);
            }
            break;
        case 53:
            {
                *out_value = MBEDTLS_ECP_DP_SECP256K1;
            }
            break;
        case 54:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
            }
            break;
        case 55:
            {
                *out_value = MBEDTLS_ECP_DP_BP384R1;
            }
            break;
        case 56:
            {
                *out_value = MBEDTLS_MD_SHA384;
            }
            break;
        case 57:
            {
                *out_value = MBEDTLS_MD_SHA512;
            }
            break;
        case 58:
            {
                *out_value = MBEDTLS_PK_NONE;
            }
            break;
        case 59:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE;
            }
            break;
        case 60:
            {
                *out_value = PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 61:
            {
                *out_value = PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 62:
            {
                *out_value = PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_SIGN_MESSAGE;
            }
            break;
        case 63:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH;
            }
            break;
        case 64:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 65:
            {
                *out_value = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256);
            }
            break;
        case 66:
            {
                *out_value = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_512);
            }
            break;
        case 67:
            {
                *out_value = PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_ANY_HASH);
            }
            break;
        case 68:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 69:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH;
            }
            break;
        case 70:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 71:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_ENCRYPT;
            }
            break;
        case 72:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE;
            }
            break;
        case 73:
            {
                *out_value = PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_SHA_256);
            }
            break;
        case 74:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 75:
            {
                *out_value = PSA_ALG_ECDSA_ANY;
            }
            break;
        case 76:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DERIVE;
            }
            break;
#endif

#line 82 "suites/main_test.function"
        default:
        {
            ret = KEY_VALUE_MAPPING_NOT_FOUND;
        }
        break;
    }
    return ret;
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param dep_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check(int dep_id)
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch (dep_id) {
    
#if defined(MBEDTLS_PK_C)

        case 0:
            {
#if defined(MBEDTLS_RSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_GENPRIME)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP192R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_ECP_HAVE_CURVE25519)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_ECP_HAVE_CURVE448)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP521R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(MBEDTLS_MD_CAN_SHA1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(MBEDTLS_PKCS1_V15)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 13:
            {
#if defined(MBEDTLS_ECP_HAVE_BP256R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 14:
            {
#if defined(MBEDTLS_ECP_HAVE_BP512R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 15:
            {
#if (MBEDTLS_RSA_GEN_KEY_MIN_BITS>=512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 16:
            {
#if defined(MBEDTLS_PKCS1_V21)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 17:
            {
#if defined(MBEDTLS_MD_CAN_SHA256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 18:
            {
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 19:
            {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 20:
            {
#if defined(MBEDTLS_PEM_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 21:
            {
#if defined(MBEDTLS_HAVE_INT64)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 22:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP192K1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 23:
            {
#if defined(MBEDTLS_ECP_HAVE_SECP256K1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 24:
            {
#if defined(MBEDTLS_ECP_HAVE_BP384R1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 25:
            {
#if defined(MBEDTLS_PK_WRITE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 26:
            {
#if (MBEDTLS_RSA_GEN_KEY_MIN_BITS<=2048)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 27:
            {
#if defined(MBEDTLS_MD_CAN_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 28:
            {
#if defined(MBEDTLS_MD_CAN_SHA512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 29:
            {
#if defined(MBEDTLS_TEST_PSA_ECC_AT_LEAST_ONE_CURVE)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 30:
            {
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 31:
            {
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 32:
            {
#if defined(PSA_WANT_ECC_SECP_R1_256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 112 "suites/main_test.function"
        default:
            break;
    }
    return ret;
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 * A test function wrapper decodes the parameters and passes them to the
 * underlying test function. Both the wrapper and the underlying function
 * return void. Test wrappers assume that they are passed a suitable
 * parameter array and do not perform any error detection.
 *
 * \param param_array   The array of parameters. Each element is a `void *`
 *                      which the wrapper casts to the correct type and
 *                      dereferences. Each wrapper function hard-codes the
 *                      number and types of the parameters.
 */
typedef void (*TestWrapper_t)(void **param_array);


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
    /* Function Id: 0 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_USE_PSA_CRYPTO)
    test_pk_psa_utils_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_USE_PSA_CRYPTO)
    test_pk_can_do_ext_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PK_C)
    test_pk_invalid_param_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PK_C)
    test_valid_parameters_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_WRITE_C)
    test_valid_parameters_pkwrite_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_PK_C)
    test_pk_utils_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_FS_IO)
    test_mbedtls_pk_check_pair_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C)
    test_pk_rsa_verify_test_vec_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C)
    test_pk_rsa_verify_ext_test_vec_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
    test_pk_ec_test_vec_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_ECP_RESTARTABLE) && defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC)
    test_pk_sign_verify_restart_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_MD_CAN_SHA256)
    test_pk_sign_verify_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C)
    test_pk_rsa_encrypt_decrypt_test_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C)
    test_pk_rsa_decrypt_test_vec_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_USE_PSA_CRYPTO)
    test_pk_wrap_rsa_decrypt_test_vec_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_PK_C)
    test_pk_ec_nocrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C)
    test_pk_rsa_overflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
    test_pk_rsa_alt_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_MD_CAN_SHA256) && defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_TEST_PK_PSA_SIGN)
    test_pk_psa_sign_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_GENPRIME)
    test_pk_sign_ext_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && defined(MBEDTLS_USE_PSA_CRYPTO)
    test_pk_psa_wrap_sign_ext_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PSA_CRYPTO_C)
    test_pk_get_psa_attributes_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21) && defined(MBEDTLS_GENPRIME)
    test_pk_rsa_v21_get_psa_attributes_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PSA_CRYPTO_C)
    test_pk_get_psa_attributes_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_USE_PSA_CRYPTO)
    test_pk_get_psa_attributes_opaque_wrapper,
#else
    NULL,
#endif

#line 145 "suites/main_test.function"
};

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param func_idx    Test function index.
 * \param params      The array of parameters to pass to the test function.
 *                    It will be decoded by the #TestWrapper_t wrapper function.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test(size_t func_idx, void **params)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs) / sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp) {
            #if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
            mbedtls_test_enable_insecure_external_rng();
            #endif

            fp(params);

            #if defined(MBEDTLS_TEST_MUTEX_USAGE)
            mbedtls_test_mutex_usage_check();
            #endif /* MBEDTLS_TEST_MUTEX_USAGE */
        } else {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


/**
 * \brief       Checks if test function is supported in this build-time
 *              configuration.
 *
 * \param func_idx    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test(size_t func_idx)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs)/sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp == NULL) {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string(char **str)
{
    if ((*str)[0] != '"' ||
        (*str)[strlen(*str) - 1] != '"') {
        mbedtls_fprintf(stderr,
                        "Expected string (with \"\") for parameter and got: %s\n", *str);
        return -1;
    }

    (*str)++;
    (*str)[strlen(*str) - 1] = '\0';

    return 0;
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param p_value Pointer to output value.
 *
 * \return      0 if success else 1
 */
int verify_int(char *str, intmax_t *p_value)
{
    char *end = NULL;
    errno = 0;
    /* Limit the range to long: for large integers, the test framework will
     * use expressions anyway. */
    long value = strtol(str, &end, 0);
    if (errno == EINVAL || *end != '\0') {
        mbedtls_fprintf(stderr,
                        "Expected integer for parameter and got: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    if (errno == ERANGE) {
        mbedtls_fprintf(stderr, "Integer out of range: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    *p_value = value;
    return 0;
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int get_line(FILE *f, char *buf, size_t len)
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do {
        ret = fgets(buf, len, f);
        if (ret == NULL) {
            return -1;
        }

        str_len = strlen(buf);

        /* Skip empty line and comment */
        if (str_len == 0 || buf[0] == '#') {
            continue;
        }
        has_string = 0;
        for (i = 0; i < str_len; i++) {
            char c = buf[i];
            if (c != ' ' && c != '\t' && c != '\n' &&
                c != '\v' && c != '\f' && c != '\r') {
                has_string = 1;
                break;
            }
        }
    } while (!has_string);

    /* Strip new line and carriage return */
    ret = buf + strlen(buf);
    if (ret-- > buf && *ret == '\n') {
        *ret = '\0';
    }
    if (ret-- > buf && *ret == '\r') {
        *ret = '\0';
    }

    return 0;
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments(char *buf, size_t len, char **params,
                           size_t params_len)
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while (*p != '\0' && p < (buf + len)) {
        if (*p == '\\') {
            p++;
            p++;
            continue;
        }
        if (*p == ':') {
            if (p + 1 < buf + len) {
                cur = p + 1;
                TEST_HELPER_ASSERT(cnt < params_len);
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace backslash escapes in strings */
    for (i = 0; i < cnt; i++) {
        p = params[i];
        q = params[i];

        while (*p != '\0') {
            if (*p == '\\') {
                ++p;
                switch (*p) {
                    case 'n':
                        *p = '\n';
                        break;
                    default:
                        // Fall through to copying *p
                        break;
                }
            }
            *(q++) = *(p++);
        }
        *q = '\0';
    }

    return cnt;
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params(size_t cnt, char **params,
                          mbedtls_test_argument_t *int_params_store)
{
    char **cur = params;
    char **out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while (cur < params + cnt) {
        char *type = *cur++;
        char *val = *cur++;

        if (strcmp(type, "char*") == 0) {
            if (verify_string(&val) == 0) {
                *out++ = val;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "int") == 0) {
            if (verify_int(val, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "hex") == 0) {
            if (verify_string(&val) == 0) {
                size_t len;

                TEST_HELPER_ASSERT(
                    mbedtls_test_unhexify((unsigned char *) val, strlen(val),
                                          val, &len) == 0);

                int_params_store->len = len;
                *out++ = val;
                *out++ = (char *) (int_params_store++);
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "exp") == 0) {
            int exp_id = strtol(val, NULL, 10);
            if (get_expression(exp_id, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else {
            ret = (DISPATCH_INVALID_TEST_DATA);
            break;
        }
    }
    return ret;
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf(size_t n, const char *ref_buf, int ref_ret)
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if (n >= sizeof(buf)) {
        return -1;
    }
    ret = mbedtls_snprintf(buf, n, "%s", "123");
    if (ret < 0 || (size_t) ret >= n) {
        ret = -1;
    }

    if (strncmp(ref_buf, buf, sizeof(buf)) != 0 ||
        ref_ret != ret ||
        memcmp(buf + n, ref + n, sizeof(buf) - n) != 0) {
        return 1;
    }

    return 0;
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf(void)
{
    return test_snprintf(0, "xxxxxxxxx",  -1) != 0 ||
           test_snprintf(1, "",           -1) != 0 ||
           test_snprintf(2, "1",          -1) != 0 ||
           test_snprintf(3, "12",         -1) != 0 ||
           test_snprintf(4, "123",         3) != 0 ||
           test_snprintf(5, "123",         3) != 0;
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry(FILE *outcome_file,
                                const char *argv0,
                                const char *test_case)
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if (outcome_file == NULL) {
        return;
    }

    if (platform == NULL) {
        platform = getenv("MBEDTLS_TEST_PLATFORM");
        if (platform == NULL) {
            platform = "unknown";
        }
    }
    if (configuration == NULL) {
        configuration = getenv("MBEDTLS_TEST_CONFIGURATION");
        if (configuration == NULL) {
            configuration = "unknown";
        }
    }
    if (test_suite == NULL) {
        test_suite = strrchr(argv0, '/');
        if (test_suite != NULL) {
            test_suite += 1; // skip the '/'
        } else {
            test_suite = argv0;
        }
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf(outcome_file, "%s;%s;%s;%s;",
                    platform, configuration, test_suite, test_case);
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret                        The test dispatch status (DISPATCH_xxx).
 */
static void write_outcome_result(FILE *outcome_file,
                                 size_t unmet_dep_count,
                                 int unmet_dependencies[],
                                 int missing_unmet_dependencies,
                                 int ret)
{
    if (outcome_file == NULL) {
        return;
    }

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch (ret) {
        case DISPATCH_TEST_SUCCESS:
            if (unmet_dep_count > 0) {
                size_t i;
                mbedtls_fprintf(outcome_file, "SKIP");
                for (i = 0; i < unmet_dep_count; i++) {
                    mbedtls_fprintf(outcome_file, "%c%d",
                                    i == 0 ? ';' : ':',
                                    unmet_dependencies[i]);
                }
                if (missing_unmet_dependencies) {
                    mbedtls_fprintf(outcome_file, ":...");
                }
                break;
            }
            switch (mbedtls_test_get_result()) {
                case MBEDTLS_TEST_RESULT_SUCCESS:
                    mbedtls_fprintf(outcome_file, "PASS;");
                    break;
                case MBEDTLS_TEST_RESULT_SKIPPED:
                    mbedtls_fprintf(outcome_file, "SKIP;Runtime skip");
                    break;
                default:
                    mbedtls_fprintf(outcome_file, "FAIL;%s:%d:%s",
                                    mbedtls_get_test_filename(),
                                    mbedtls_test_get_line_no(),
                                    mbedtls_test_get_test());
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf(outcome_file, "FAIL;Test function not found");
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf(outcome_file, "FAIL;Invalid test data");
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf(outcome_file, "SKIP;Unsupported suite");
            break;
        default:
            mbedtls_fprintf(outcome_file, "FAIL;Unknown cause");
            break;
    }
    mbedtls_fprintf(outcome_file, "\n");
    fflush(outcome_file);
}

#if defined(__unix__) ||                                \
    (defined(__APPLE__) && defined(__MACH__))
#define MBEDTLS_HAVE_CHDIR
#endif

#if defined(MBEDTLS_HAVE_CHDIR)
/** Try chdir to the directory containing argv0.
 *
 * Failures are silent.
 */
static void try_chdir_if_supported(const char *argv0)
{
    /* We might want to allow backslash as well, for Windows. But then we also
     * need to consider chdir() vs _chdir(), and different conventions
     * regarding paths in argv[0] (naively enabling this code with
     * backslash support on Windows leads to chdir into the wrong directory
     * on the CI). */
    const char *slash = strrchr(argv0, '/');
    if (slash == NULL) {
        return;
    }
    size_t path_size = slash - argv0 + 1;
    char *path = mbedtls_calloc(1, path_size);
    if (path == NULL) {
        return;
    }
    memcpy(path, argv0, path_size - 1);
    path[path_size - 1] = 0;
    int ret = chdir(path);
    if (ret != 0) {
        mbedtls_fprintf(stderr, "%s: note: chdir(\"%s\") failed.\n",
                        __func__, path);
    }
    mbedtls_free(path);
}
#else /* MBEDTLS_HAVE_CHDIR */
/* No chdir() or no support for parsing argv[0] on this platform. */
static void try_chdir_if_supported(const char *argv0)
{
    (void) argv0;
    return;
}
#endif /* MBEDTLS_HAVE_CHDIR */

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests(int argc, const char **argv)
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_pk.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    int ret;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for processed integer params. */
    mbedtls_test_argument_t int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv("MBEDTLS_TEST_OUTCOME_FILE");
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset(&pointer, 0, sizeof(void *));
    if (pointer != NULL) {
        mbedtls_fprintf(stderr, "all-bits-zero is not a NULL pointer\n");
        return 1;
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if (run_test_snprintf() != 0) {
        mbedtls_fprintf(stderr, "the snprintf implementation is broken\n");
        return 1;
    }

    if (outcome_file_name != NULL && *outcome_file_name != '\0') {
        outcome_file = fopen(outcome_file_name, "a");
        if (outcome_file == NULL) {
            mbedtls_fprintf(stderr, "Unable to open outcome file. Continuing anyway.\n");
        }
    }

    while (arg_index < argc) {
        next_arg = argv[arg_index];

        if (strcmp(next_arg, "--verbose") == 0 ||
            strcmp(next_arg, "-v") == 0) {
            option_verbose = 1;
        } else if (strcmp(next_arg, "--help") == 0 ||
                   strcmp(next_arg, "-h") == 0) {
            mbedtls_fprintf(stdout, USAGE);
            mbedtls_exit(EXIT_SUCCESS);
        } else {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[arg_index];
            testfile_count = argc - arg_index;
            break;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if (test_files == NULL || testfile_count == 0) {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    mbedtls_test_info_reset();

    /* Now begin to execute the tests in the testfiles */
    for (testfile_index = 0;
         testfile_index < testfile_count;
         testfile_index++) {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[testfile_index];

        file = fopen(test_filename, "r");
        if (file == NULL) {
            mbedtls_fprintf(stderr, "Failed to open test file: %s\n",
                            test_filename);
            if (outcome_file != NULL) {
                fclose(outcome_file);
            }
            return 1;
        }

        while (!feof(file)) {
            if (unmet_dep_count > 0) {
                mbedtls_fprintf(stderr,
                                "FATAL: Dep count larger than zero at start of loop\n");
                mbedtls_exit(MBEDTLS_EXIT_FAILURE);
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            mbedtls_fprintf(stdout, "%s%.66s",
                            mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_FAILED ?
                            "\n" : "", buf);
            mbedtls_fprintf(stdout, " ");
            for (i = strlen(buf) + 1; i < 67; i++) {
                mbedtls_fprintf(stdout, ".");
            }
            mbedtls_fprintf(stdout, " ");
            fflush(stdout);
            write_outcome_entry(outcome_file, argv[0], buf);

            total_tests++;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            cnt = parse_arguments(buf, strlen(buf), params,
                                  sizeof(params) / sizeof(params[0]));

            if (strcmp(params[0], "depends_on") == 0) {
                for (i = 1; i < cnt; i++) {
                    int dep_id = strtol(params[i], NULL, 10);
                    if (dep_check(dep_id) != DEPENDENCY_SUPPORTED) {
                        if (unmet_dep_count <
                            ARRAY_LENGTH(unmet_dependencies)) {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        } else {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                    break;
                }
                cnt = parse_arguments(buf, strlen(buf), params,
                                      sizeof(params) / sizeof(params[0]));
            }

            // If there are no unmet dependencies execute the test
            if (unmet_dep_count == 0) {
                mbedtls_test_info_reset();

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if (!option_verbose) {
                    stdout_fd = redirect_output(stdout, "/dev/null");
                    if (stdout_fd == -1) {
                        /* Redirection has failed with no stdout so exit */
                        exit(1);
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul(params[0], NULL, 10);
                if ((ret = check_test(function_id)) == DISPATCH_TEST_SUCCESS) {
                    ret = convert_params(cnt - 1, params + 1, int_params);
                    if (DISPATCH_TEST_SUCCESS == ret) {
                        ret = dispatch_test(function_id, (void **) (params + 1));
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if (!option_verbose && restore_output(stdout, stdout_fd)) {
                    /* Redirection has failed with no stdout so exit */
                    exit(1);
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result(outcome_file,
                                 unmet_dep_count, unmet_dependencies,
                                 missing_unmet_dependencies,
                                 ret);
            if (unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE) {
                total_skipped++;
                mbedtls_fprintf(stdout, "----");

                if (1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE) {
                    mbedtls_fprintf(stdout, "\n   Test Suite not enabled");
                }

                if (1 == option_verbose && unmet_dep_count > 0) {
                    mbedtls_fprintf(stdout, "\n   Unmet dependencies: ");
                    for (i = 0; i < unmet_dep_count; i++) {
                        mbedtls_fprintf(stdout, "%d ",
                                        unmet_dependencies[i]);
                    }
                    if (missing_unmet_dependencies) {
                        mbedtls_fprintf(stdout, "...");
                    }
                }
                mbedtls_fprintf(stdout, "\n");
                fflush(stdout);

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            } else if (ret == DISPATCH_TEST_SUCCESS) {
                if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SUCCESS) {
                    mbedtls_fprintf(stdout, "PASS\n");
                } else if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SKIPPED) {
                    mbedtls_fprintf(stdout, "----\n");
                    total_skipped++;
                } else {
                    char line_buffer[MBEDTLS_TEST_LINE_LENGTH];

                    total_errors++;
                    mbedtls_fprintf(stdout, "FAILED\n");
                    mbedtls_fprintf(stdout, "  %s\n  at ",
                                    mbedtls_test_get_test());
                    if (mbedtls_test_get_step() != (unsigned long) (-1)) {
                        mbedtls_fprintf(stdout, "step %lu, ",
                                        mbedtls_test_get_step());
                    }
                    mbedtls_fprintf(stdout, "line %d, %s",
                                    mbedtls_test_get_line_no(),
                                    mbedtls_get_test_filename());

                    mbedtls_test_get_line1(line_buffer);
                    if (line_buffer[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s", line_buffer);
                    }
                    mbedtls_test_get_line2(line_buffer);
                    if (line_buffer[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s", line_buffer);
                    }
                }
                fflush(stdout);
            } else if (ret == DISPATCH_INVALID_TEST_DATA) {
                mbedtls_fprintf(stderr, "FAILED: FATAL PARSE ERROR\n");
                fclose(file);
                mbedtls_exit(2);
            } else if (ret == DISPATCH_TEST_FN_NOT_FOUND) {
                mbedtls_fprintf(stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n");
                fclose(file);
                mbedtls_exit(2);
            } else {
                total_errors++;
            }
        }
        fclose(file);
    }

    if (outcome_file != NULL) {
        fclose(outcome_file);
    }

    mbedtls_fprintf(stdout,
                    "\n----------------------------------------------------------------------------\n\n");
    if (total_errors == 0) {
        mbedtls_fprintf(stdout, "PASSED");
    } else {
        mbedtls_fprintf(stdout, "FAILED");
    }

    mbedtls_fprintf(stdout, " (%u / %u tests (%u skipped))\n",
                    total_tests - total_errors, total_tests, total_skipped);

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_end();
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return total_errors != 0;
}


#line 217 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main(int argc, const char *argv[])
{
#if defined(MBEDTLS_TEST_HOOKS)
    extern void (*mbedtls_test_hook_test_fail)(const char *test, int line, const char *file);
    mbedtls_test_hook_test_fail = &mbedtls_test_fail;
#if defined(MBEDTLS_ERROR_C)
    mbedtls_test_hook_error_add = &mbedtls_test_err_add_check;
#endif
#endif

    /* Try changing to the directory containing the executable, if
     * using the default data file. This allows running the executable
     * from another directory (e.g. the project root) and still access
     * the .datax file as well as data files used by test cases
     * (typically from tests/data_files).
     *
     * Note that we do this before the platform setup (which may access
     * files such as a random seed). We also do this before accessing
     * test-specific files such as the outcome file, which is arguably
     * not desirable and should be fixed later.
     */
    if (argc == 1) {
        try_chdir_if_supported(argv[0]);
    }

    int ret = mbedtls_test_platform_setup();
    if (ret != 0) {
        mbedtls_fprintf(stderr,
                        "FATAL: Failed to initialize platform - error %d\n",
                        ret);
        return -1;
    }

    ret = execute_tests(argc, argv);
    mbedtls_test_platform_teardown();
    return ret;
}
