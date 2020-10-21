// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _CRT_RAND_S

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <openenclave/internal/tests.h>
#include "include_openssl.h"
#include "openssl_moretest_u.h"

#include "CSchema_checker.h"

static t_openssl_schema _openssl_akamai[] = {
    {"EC_Key",
     e_EC_Key,
     1,
     {sizeof(int), _Neg, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg},
     {S_FIXLEN_IN | S_RAND, 0, 0, 0, 0, 0, 0, 0, 0}},
    {"OBJ_txt2nid",
     e_OBJ_txt2nid,
     3,
     {sizeof(int), sizeof(int), _ELLEPH, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg},
     {S_FIXLEN_IN | S_RAND,
      S_FIXLEN_O | S_RAND,
      S_FIXLEN_O | S_RAND,
      0,
      0,
      0,
      0,
      0,
      0}},
    {"i2d_Key",
     e_i2d_PrivateKey,
     1,
     {sizeof(int), _Neg, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg, _Neg},
     {S_FIXLEN_O | S_RAND, 0, 0, 0, 0, 0, 0, 0, 0}},
};

static t_openssl_schema* get_schema()
{
    return _openssl_akamai;
}

static uint get_schema_length()
{
    return sizeof(_openssl_akamai) / sizeof(_openssl_akamai[0]);
}

class CSchemaChecker_Akamai : public CSchemaChecker
{
  public:
    CSchemaChecker_Akamai(t_openssl_schema* schema, uint schema_size)
        : CSchemaChecker(schema, schema_size)
    {
    }
};

oe_result_t akamai_test_group(oe_enclave_t* enclave)
{
    oe_result_t result;
    int retval;
    uint num_apis = get_schema_length();
    t_openssl_schema* schema = get_schema();
    CSchemaChecker_Akamai* checker =
        new CSchemaChecker_Akamai(schema, num_apis);
    printf("total test number: %u\n", num_apis);

    for (int i = 0; i < (int)num_apis; i++)
    {
        printf("Test case: %s\tstarts \n", (schema + i)->api_name);
        checker->SetupParams((schema + i)->id, (uint32_t)i);
        result =
            ecall_akamai_tests(enclave, &retval, (void*)(&(checker->m_p1)));
        OE_TEST(result == OE_OK);
        OE_TEST(retval == 0);
        printf("Test case: %s\tends \n", (schema + i)->api_name);
    }
    return OE_OK;
}
