// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#define _CRT_RAND_S

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <openenclave/internal/tests.h>
#include "openssl_moretest_u.h"

#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "CSchema_checker.h"

t_openssl_schema _openssl_keygen[] = {
    {"EVP_PKEY_assign_test",
     e_EVP_PKEY_assign,
     1,
     {sizeof(int), _Neg, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg},
     {S_FIXLEN_IO | _RAND, 0, 0, 0, 0, 0, 0, 0, 0}},
};

t_openssl_schema* get_keygen_schema()
{
    return _openssl_keygen;
}

uint get_keygen_schema_length()
{
    return sizeof(_openssl_keygen) / sizeof(_openssl_keygen[0]);
}

class CSchemaChecker_Keygen : public CSchemaChecker
{
  public:
    CSchemaChecker_Keygen(t_openssl_schema* schema, uint schema_size)
        : CSchemaChecker(schema, schema_size)
    {
    }
    // override
    void OverideRandomizedValue(
        openssl_api_id id,
        uint param_no,
        uint64_t type,
        uint origin,
        uint8_t* buf,
        uint buflen);
};

void CSchemaChecker_Keygen::OverideRandomizedValue(
    openssl_api_id id,
    uint param_no,
    uint64_t type,
    uint origin,
    uint8_t* buf,
    uint buflen)
{
    if (id == e_EVP_PKEY_assign && param_no == 0)
    {
        uint v = *(uint*)buf;
        v = v % 9;
        *(uint*)buf = v;
    }
    else
    {
        CSchemaChecker::OverideRandomizedValue(
            id, param_no, type, origin, buf, buflen);
    }
}

oe_result_t schema_test_keygen(oe_enclave_t* enclave)
{
    oe_result_t result;
    int retval;
    uint num_apis = get_keygen_schema_length();
    t_openssl_schema* schema = get_keygen_schema();
    CSchemaChecker_Keygen* checker =
        new CSchemaChecker_Keygen(schema, num_apis);
    printf("total test number: %u\n", num_apis);

    for (int i = 0; i < (int)num_apis; i++)
    {
        checker->SetupParams((schema + i)->id, (uint32_t)i);
        printf("Test case: %s\tstarts \n", (schema + i)->api_name);
        result =
            ecall_keygen_tests(enclave, &retval, (void*)(&(checker->m_p1)));
        OE_TEST(result == OE_OK);
        OE_TEST(retval >= 0);
        printf("Test case: %s\tends \n", (schema + i)->api_name);
    }
    return OE_OK;
}
