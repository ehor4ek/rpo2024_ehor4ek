#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_md.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/main_test.function
 *      Platform code file  : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/host_test.function
 *      Helper file         : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/helpers.function
 *      Test suite file     : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function
 *      Test suite data     : /home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.data
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

#if defined(MBEDTLS_MD_LIGHT)
#line 2 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
#include "mbedtls/md.h"
#include "mbedtls/psa_util.h"

#include "mbedtls/oid.h"
#include "mbedtls/asn1.h"

#define MD_PSA(md, psa) \
    TEST_EQUAL(mbedtls_md_psa_alg_from_type(md), psa);  \
    TEST_EQUAL(mbedtls_md_type_from_psa_alg(psa), md);
#if defined(MBEDTLS_MD_C)
#line 19 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_mbedtls_md_list(void)
{
    const int *md_type_ptr;
    const mbedtls_md_info_t *info;
    mbedtls_md_context_t ctx;
    unsigned char out[MBEDTLS_MD_MAX_SIZE] = { 0 };

    MD_PSA_INIT();
    mbedtls_md_init(&ctx);

    /*
     * Test that mbedtls_md_list() only returns valid MDs.
     */
    for (md_type_ptr = mbedtls_md_list(); *md_type_ptr != 0; md_type_ptr++) {
        info = mbedtls_md_info_from_type(*md_type_ptr);
        TEST_ASSERT(info != NULL);
        TEST_EQUAL(0, mbedtls_md_setup(&ctx, info, 0));
        TEST_EQUAL(0, mbedtls_md_starts(&ctx));
        TEST_EQUAL(0, mbedtls_md_finish(&ctx, out));
        mbedtls_md_free(&ctx);

#if defined(MBEDTLS_PSA_CRYPTO_C)
        /* Ensure that we can convert to and from a psa_algorithm_t */
        psa_algorithm_t p = mbedtls_md_psa_alg_from_type(*md_type_ptr);
        TEST_ASSERT(p != PSA_ALG_NONE);
        TEST_EQUAL(*md_type_ptr, mbedtls_md_type_from_psa_alg(p));
#endif

#if defined(MBEDTLS_OID_C)
        mbedtls_asn1_buf asn1;
        /* Check that we have an OID definition */
        TEST_EQUAL(mbedtls_oid_get_oid_by_md((mbedtls_md_type_t) *md_type_ptr,
                                             (const char **) &asn1.p, &asn1.len), 0);
        /* Check that this OID definition maps back to the correct mbedtls_md_type_t */
        mbedtls_md_type_t m;
        TEST_EQUAL(mbedtls_oid_get_md_alg(&asn1, &m), 0);
        TEST_EQUAL(m, *md_type_ptr);
#endif
    }

exit:
    mbedtls_md_free(&ctx);
    MD_PSA_DONE();
}

void test_mbedtls_md_list_wrapper( void ** params )
{
    (void)params;

    test_mbedtls_md_list(  );
}
#endif /* MBEDTLS_MD_C */
#if defined(MBEDTLS_PSA_CRYPTO_C)
#line 66 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_to_from_psa(void)
{
    /* We use a simplified implementation that relies on numerical values
     * being aligned, so make sure they remain so. */
    MD_PSA(MBEDTLS_MD_MD5, PSA_ALG_MD5);
    MD_PSA(MBEDTLS_MD_RIPEMD160, PSA_ALG_RIPEMD160);
    MD_PSA(MBEDTLS_MD_SHA1, PSA_ALG_SHA_1);
    MD_PSA(MBEDTLS_MD_SHA224, PSA_ALG_SHA_224);
    MD_PSA(MBEDTLS_MD_SHA256, PSA_ALG_SHA_256);
    MD_PSA(MBEDTLS_MD_SHA384, PSA_ALG_SHA_384);
    MD_PSA(MBEDTLS_MD_SHA512, PSA_ALG_SHA_512);
    MD_PSA(MBEDTLS_MD_SHA3_224, PSA_ALG_SHA3_224);
    MD_PSA(MBEDTLS_MD_SHA3_256, PSA_ALG_SHA3_256);
    MD_PSA(MBEDTLS_MD_SHA3_384, PSA_ALG_SHA3_384);
    MD_PSA(MBEDTLS_MD_SHA3_512, PSA_ALG_SHA3_512);

    /* Don't test for NONE<->NONE as this is not guaranteed */
exit:
    ;
}

void test_md_to_from_psa_wrapper( void ** params )
{
    (void)params;

    test_md_to_from_psa(  );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
#line 87 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_null_args(void)
{
    mbedtls_md_context_t ctx;
#if defined(MBEDTLS_MD_C)
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(*(mbedtls_md_list()));
#endif
    unsigned char buf[1] = { 0 };

    MD_PSA_INIT();
    mbedtls_md_init(&ctx);

    TEST_EQUAL(0, mbedtls_md_get_size(NULL));
#if defined(MBEDTLS_MD_C)
    TEST_EQUAL(mbedtls_md_get_type(NULL), MBEDTLS_MD_NONE);
    TEST_ASSERT(mbedtls_md_get_name(NULL) == NULL);

    TEST_ASSERT(mbedtls_md_info_from_string(NULL) == NULL);
    TEST_ASSERT(mbedtls_md_info_from_ctx(NULL) == NULL);
    TEST_ASSERT(mbedtls_md_info_from_ctx(&ctx) == NULL);
#endif /* MBEDTLS_MD_C */

    TEST_EQUAL(mbedtls_md_setup(&ctx, NULL, 0), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
#if defined(MBEDTLS_MD_C)
    TEST_EQUAL(mbedtls_md_setup(NULL, info, 0), MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_starts(NULL), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_starts(&ctx), MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_update(NULL, buf, 1), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_update(&ctx, buf, 1), MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_finish(NULL, buf), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_finish(&ctx, buf), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
#endif

    TEST_EQUAL(mbedtls_md(NULL, buf, 1, buf), MBEDTLS_ERR_MD_BAD_INPUT_DATA);

#if defined(MBEDTLS_MD_C)
#if defined(MBEDTLS_FS_IO)
    TEST_EQUAL(mbedtls_md_file(NULL, "", buf), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
#endif

    TEST_EQUAL(mbedtls_md_hmac_starts(NULL, buf, 1),
               MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_hmac_starts(&ctx, buf, 1),
               MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_hmac_update(NULL, buf, 1),
               MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_hmac_update(&ctx, buf, 1),
               MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_hmac_finish(NULL, buf), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_hmac_finish(&ctx, buf), MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_hmac_reset(NULL), MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    TEST_EQUAL(mbedtls_md_hmac_reset(&ctx), MBEDTLS_ERR_MD_BAD_INPUT_DATA);

    TEST_EQUAL(mbedtls_md_hmac(NULL, buf, 1, buf, 1, buf),
               MBEDTLS_ERR_MD_BAD_INPUT_DATA);
#endif /* MBEDTLS_MD_C */

    /* Ok, this is not NULL arg but NULL return... */
    TEST_ASSERT(mbedtls_md_info_from_type(MBEDTLS_MD_NONE) == NULL);
#if defined(MBEDTLS_MD_C)
    TEST_ASSERT(mbedtls_md_info_from_string("no such md") == NULL);
#endif

exit:
    MD_PSA_DONE();
}

void test_md_null_args_wrapper( void ** params )
{
    (void)params;

    test_md_null_args(  );
}
#line 161 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_info(int md_type, char *md_name, int md_size)
{
    const mbedtls_md_info_t *md_info;
#if defined(MBEDTLS_MD_C)
    const int *md_type_ptr;
#else
    (void) md_name;
#endif

    /* Note: PSA Crypto init not needed for info functions */

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);
#if defined(MBEDTLS_MD_C)
    TEST_ASSERT(md_info == mbedtls_md_info_from_string(md_name));
#endif

    TEST_EQUAL(mbedtls_md_get_type(md_info), (mbedtls_md_type_t) md_type);
    TEST_EQUAL(mbedtls_md_get_size(md_info), (unsigned char) md_size);
#if defined(MBEDTLS_MD_C)
    TEST_EQUAL(0, strcmp(mbedtls_md_get_name(md_info), md_name));

    int found = 0;
    for (md_type_ptr = mbedtls_md_list(); *md_type_ptr != 0; md_type_ptr++) {
        if (*md_type_ptr == md_type) {
            found = 1;
        }
    }
    TEST_EQUAL(found, 1);
#endif /* MBEDTLS_MD_C */
exit:
    ;
}

void test_md_info_wrapper( void ** params )
{

    test_md_info( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], ((mbedtls_test_argument_t *) params[2])->sint );
}
#line 195 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_text(int md_type, char *text_src_string, data_t *hash)
{
    unsigned char *src = (unsigned char *) text_src_string;
    size_t src_len = strlen(text_src_string);
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    const mbedtls_md_info_t *md_info = NULL;

    MD_PSA_INIT();

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);

    TEST_EQUAL(0, mbedtls_md(md_info, src, src_len, output));

    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

exit:
    MD_PSA_DONE();
}

void test_md_text_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_md_text( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], &data2 );
}
#line 217 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_hex(int md_type, data_t *src_str, data_t *hash)
{
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    const mbedtls_md_info_t *md_info = NULL;

    MD_PSA_INIT();

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);

    TEST_EQUAL(0, mbedtls_md(md_info, src_str->x, src_str->len, output));


    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

exit:
    MD_PSA_DONE();
}

void test_md_hex_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_md_hex( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3 );
}
#line 238 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_text_multi(int md_type, char *text_src_string,
                   data_t *hash)
{
    unsigned char *src = (unsigned char *) text_src_string;
    size_t src_len = strlen(text_src_string);
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    size_t halfway;

    const mbedtls_md_info_t *md_info = NULL;
    mbedtls_md_context_t ctx, ctx_copy;

    MD_PSA_INIT();

    mbedtls_md_init(&ctx);
    mbedtls_md_init(&ctx_copy);

    halfway = src_len / 2;

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);
    TEST_EQUAL(0, mbedtls_md_setup(&ctx, md_info, 0));
    TEST_EQUAL(0, mbedtls_md_setup(&ctx_copy, md_info, 0));
#if defined(MBEDTLS_MD_C)
    TEST_ASSERT(mbedtls_md_info_from_ctx(&ctx) == md_info);
    TEST_ASSERT(mbedtls_md_info_from_ctx(&ctx_copy) == md_info);
#endif /* MBEDTLS_MD_C */

    TEST_EQUAL(0, mbedtls_md_starts(&ctx));
    TEST_ASSERT(ctx.md_ctx != NULL);
    TEST_EQUAL(0, mbedtls_md_update(&ctx, src, halfway));
    TEST_EQUAL(0, mbedtls_md_clone(&ctx_copy, &ctx));

    TEST_EQUAL(0, mbedtls_md_update(&ctx, src + halfway, src_len - halfway));
    TEST_EQUAL(0, mbedtls_md_finish(&ctx, output));
    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

    /* Test clone */
    memset(output, 0x00, sizeof(output));

    TEST_EQUAL(0, mbedtls_md_update(&ctx_copy, src + halfway, src_len - halfway));
    TEST_EQUAL(0, mbedtls_md_finish(&ctx_copy, output));
    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

exit:
    mbedtls_md_free(&ctx);
    mbedtls_md_free(&ctx_copy);
    MD_PSA_DONE();
}

void test_md_text_multi_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_md_text_multi( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], &data2 );
}
#line 289 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_hex_multi(int md_type, data_t *src_str, data_t *hash)
{
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    const mbedtls_md_info_t *md_info = NULL;
    mbedtls_md_context_t ctx, ctx_copy;
    int halfway;

    MD_PSA_INIT();

    mbedtls_md_init(&ctx);
    mbedtls_md_init(&ctx_copy);

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);
    TEST_EQUAL(0, mbedtls_md_setup(&ctx, md_info, 0));
    TEST_EQUAL(0, mbedtls_md_setup(&ctx_copy, md_info, 0));
#if defined(MBEDTLS_MD_C)
    TEST_ASSERT(mbedtls_md_info_from_ctx(&ctx) == md_info);
    TEST_ASSERT(mbedtls_md_info_from_ctx(&ctx_copy) == md_info);
#endif /* MBEDTLS_MD_C */

    halfway = src_str->len / 2;

    TEST_EQUAL(0, mbedtls_md_starts(&ctx));
    TEST_ASSERT(ctx.md_ctx != NULL);
    TEST_EQUAL(0, mbedtls_md_update(&ctx, src_str->x, halfway));
    TEST_EQUAL(0, mbedtls_md_clone(&ctx_copy, &ctx));

    TEST_EQUAL(0, mbedtls_md_update(&ctx, src_str->x + halfway, src_str->len - halfway));
    TEST_EQUAL(0, mbedtls_md_finish(&ctx, output));
    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

    /* Test clone */
    memset(output, 0x00, sizeof(output));

    TEST_EQUAL(0, mbedtls_md_update(&ctx_copy, src_str->x + halfway, src_str->len - halfway));
    TEST_EQUAL(0, mbedtls_md_finish(&ctx_copy, output));
    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

exit:
    mbedtls_md_free(&ctx);
    mbedtls_md_free(&ctx_copy);
    MD_PSA_DONE();
}

void test_md_hex_multi_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], ((mbedtls_test_argument_t *) params[2])->len};
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_md_hex_multi( ((mbedtls_test_argument_t *) params[0])->sint, &data1, &data3 );
}
#if defined(MBEDTLS_MD_C)
#line 336 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_mbedtls_md_hmac(int md_type, int trunc_size,
                     data_t *key_str, data_t *src_str,
                     data_t *hash)
{
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    const mbedtls_md_info_t *md_info = NULL;

    MD_PSA_INIT();

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);


    TEST_EQUAL(0, mbedtls_md_hmac(md_info, key_str->x, key_str->len,
                                  src_str->x, src_str->len, output));

    TEST_MEMORY_COMPARE(output, trunc_size, hash->x, hash->len);

exit:
    MD_PSA_DONE();
}

void test_mbedtls_md_hmac_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_mbedtls_md_hmac( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, &data2, &data4, &data6 );
}
#endif /* MBEDTLS_MD_C */
#if defined(MBEDTLS_MD_C)
#line 360 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_hmac_multi(int md_type, int trunc_size, data_t *key_str,
                   data_t *src_str, data_t *hash)
{
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    const mbedtls_md_info_t *md_info = NULL;
    mbedtls_md_context_t ctx;
    int halfway;

    MD_PSA_INIT();

    mbedtls_md_init(&ctx);

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);
    TEST_EQUAL(0, mbedtls_md_setup(&ctx, md_info, 1));
#if defined(MBEDTLS_MD_C)
    TEST_ASSERT(mbedtls_md_info_from_ctx(&ctx) == md_info);
#endif

    halfway = src_str->len / 2;

    TEST_EQUAL(0, mbedtls_md_hmac_starts(&ctx, key_str->x, key_str->len));
    TEST_ASSERT(ctx.md_ctx != NULL);
    TEST_EQUAL(0, mbedtls_md_hmac_update(&ctx, src_str->x, halfway));
    TEST_EQUAL(0, mbedtls_md_hmac_update(&ctx, src_str->x + halfway, src_str->len - halfway));
    TEST_EQUAL(0, mbedtls_md_hmac_finish(&ctx, output));

    TEST_MEMORY_COMPARE(output, trunc_size, hash->x, hash->len);

    /* Test again, for reset() */
    memset(output, 0x00, sizeof(output));

    TEST_EQUAL(0, mbedtls_md_hmac_reset(&ctx));
    TEST_EQUAL(0, mbedtls_md_hmac_update(&ctx, src_str->x, halfway));
    TEST_EQUAL(0, mbedtls_md_hmac_update(&ctx, src_str->x + halfway, src_str->len - halfway));
    TEST_EQUAL(0, mbedtls_md_hmac_finish(&ctx, output));

    TEST_MEMORY_COMPARE(output, trunc_size, hash->x, hash->len);

exit:
    mbedtls_md_free(&ctx);
    MD_PSA_DONE();
}

void test_md_hmac_multi_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data6 = {(uint8_t *) params[6], ((mbedtls_test_argument_t *) params[7])->len};

    test_md_hmac_multi( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, &data2, &data4, &data6 );
}
#endif /* MBEDTLS_MD_C */
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_MD_C)
#line 406 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_mbedtls_md_file(int md_type, char *filename,
                     data_t *hash)
{
    unsigned char output[MBEDTLS_MD_MAX_SIZE] = { 0 };
    const mbedtls_md_info_t *md_info = NULL;

    MD_PSA_INIT();

    md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT(md_info != NULL);

    TEST_EQUAL(0, mbedtls_md_file(md_info, filename, output));

    TEST_MEMORY_COMPARE(output, mbedtls_md_get_size(md_info), hash->x, hash->len);

exit:
    MD_PSA_DONE();
}

void test_mbedtls_md_file_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_mbedtls_md_file( ((mbedtls_test_argument_t *) params[0])->sint, (char *) params[1], &data2 );
}
#endif /* MBEDTLS_MD_C */
#endif /* MBEDTLS_FS_IO */
#line 427 "/home/egor/AndroidStudioProjects/rpo2024_ehor4ek/libs/mbedtls/mbedtls/tests/suites/test_suite_md.function"
void test_md_psa_dynamic_dispatch(int md_type, int pre_psa_ret, int post_psa_engine)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    mbedtls_md_context_t ctx1, ctx2;

    /* Intentionally no PSA init here! (Will be done later.) */

    mbedtls_md_init(&ctx1);
    mbedtls_md_init(&ctx2);

    TEST_ASSERT(md_info != NULL);

    /* Before PSA crypto init */
    TEST_EQUAL(pre_psa_ret, mbedtls_md_setup(&ctx1, md_info, 0));
    TEST_EQUAL(pre_psa_ret, mbedtls_md_setup(&ctx2, md_info, 0));

#if defined(MBEDTLS_MD_SOME_PSA)
    TEST_EQUAL(ctx1.engine, MBEDTLS_MD_ENGINE_LEGACY);
    TEST_EQUAL(ctx2.engine, MBEDTLS_MD_ENGINE_LEGACY);
#endif

    /* Reset ctx1 but keep ctx2 for the cloning test */
    mbedtls_md_free(&ctx1);
    mbedtls_md_init(&ctx1);

    /* Now initilize PSA Crypto */
    MD_PSA_INIT();

    /* After PSA Crypto init */
    TEST_EQUAL(0, mbedtls_md_setup(&ctx1, md_info, 0));
#if defined(MBEDTLS_MD_SOME_PSA)
    TEST_EQUAL(ctx1.engine, post_psa_engine);
#endif

    /* Cloning test */
    if (pre_psa_ret == 0) {
        int exp_clone_ret = post_psa_engine == MBEDTLS_MD_ENGINE_PSA
                          ? MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE
                          : 0;
        TEST_EQUAL(exp_clone_ret, mbedtls_md_clone(&ctx2, &ctx1));
    }

exit:
    mbedtls_md_free(&ctx1);
    mbedtls_md_free(&ctx2);
    MD_PSA_DONE();
}

void test_md_psa_dynamic_dispatch_wrapper( void ** params )
{

    test_md_psa_dynamic_dispatch( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint );
}
#endif /* MBEDTLS_MD_LIGHT */


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
    
#if defined(MBEDTLS_MD_LIGHT)

        case 0:
            {
                *out_value = MBEDTLS_MD_MD5;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_MD_RIPEMD160;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_MD_SHA224;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_MD_SHA256;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_MD_SHA384;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_MD_SHA512;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_MD_SHA3_224;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_MD_SHA3_256;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_MD_SHA3_384;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_MD_SHA3_512;
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
    
#if defined(MBEDTLS_MD_LIGHT)

        case 0:
            {
#if defined(MBEDTLS_MD_CAN_MD5)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_MD_CAN_RIPEMD160)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_MD_CAN_SHA1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_MD_CAN_SHA224)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_MD_CAN_SHA256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_MD_CAN_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_MD_CAN_SHA512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_MD_CAN_SHA3_224)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_MD_CAN_SHA3_256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_MD_CAN_SHA3_384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if defined(MBEDTLS_MD_CAN_SHA3_512)
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

#if defined(MBEDTLS_MD_LIGHT) && defined(MBEDTLS_MD_C)
    test_mbedtls_md_list_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_MD_LIGHT) && defined(MBEDTLS_PSA_CRYPTO_C)
    test_md_to_from_psa_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_null_args_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_info_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_text_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_hex_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_text_multi_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_hex_multi_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_MD_LIGHT) && defined(MBEDTLS_MD_C)
    test_mbedtls_md_hmac_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_MD_LIGHT) && defined(MBEDTLS_MD_C)
    test_md_hmac_multi_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_MD_LIGHT) && defined(MBEDTLS_FS_IO) && defined(MBEDTLS_MD_C)
    test_mbedtls_md_file_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_MD_LIGHT)
    test_md_psa_dynamic_dispatch_wrapper,
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
    const char *default_filename = "./test_suite_md.datax";
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