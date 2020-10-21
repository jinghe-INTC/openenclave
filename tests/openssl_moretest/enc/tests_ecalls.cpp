// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include "include_openssl.h"
#include "openssl/crypto.h"
#include "openssl_moretest_t.h"
#include "openssl_schema.h"

extern int common_asym_tests(void* buf);
extern int common_akamai_tests(void* buf);
extern int common_digest_tests(void* buf);
extern int common_keygen_tests(void* buf);
extern int common_symmetric_encryption_tests(void* buf);

void ecall_set_rdrand_engine()
{
    ENGINE* eng = NULL;

    /* Initialize and opt-in the RDRAND engine. */
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
    {
        goto done;
    }

    if (!ENGINE_init(eng))
    {
        goto done;
    }

    if (!ENGINE_set_default(eng, ENGINE_METHOD_RAND))
    {
        goto done;
    }

done:

    /* cleanup to avoid memory leak. */
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();

    return;
}

int ecall_asym_tests(void* buf)
{
    return common_asym_tests(buf);
}

int ecall_akamai_tests(void* buf)
{
    return common_akamai_tests(buf);
}

int ecall_schema_run_digest_tests(void* buf)
{
    return common_digest_tests(buf);
}

int ecall_schema_run_symmetric_encryption(void* buf)
{
    return common_symmetric_encryption_tests(buf);
}

int ecall_keygen_tests(void* buf)
{
    return common_keygen_tests(buf);
}
