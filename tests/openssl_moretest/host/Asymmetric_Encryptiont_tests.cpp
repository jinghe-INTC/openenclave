// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#define _CRT_RAND_S

#include <assert.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "CSchema_checker.h"
#include "include_openssl.h"
#include "openssl_moretest_u.h"

t_openssl_schema _openssl_asym[] = {
    {"RSA_generate_key_ex",
     e_RSA_generate_key_ex,
     3,
     {sizeof(RSA),
      sizeof(int),
      sizeof(BIGNUM),
      _Neg,
      _Neg,
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_FIXLEN_IO | _RAND,
      S_FIXLEN_IO | _RAND,
      S_FIXLEN_IO | _RAND,
      0,
      0,
      0,
      0,
      0,
      0}},
    {"RSA_generate_key",
     e_RSA_generate_key,
     2,
     {sizeof(int),
      sizeof(unsigned long),
      _Neg,
      _Neg,
      _Neg,
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_FIXLEN_IO | _RAND, S_FIXLEN_IO | _RAND, 0, 0, 0, 0, 0, 0, 0}},
    //=== int RSA_public_encrypt(int flen, unsigned char *from, unsigned char
    //*to, RSA *rsa, int padding);
    {"RSA_public_encrypt",
     e_RSA_public_encrypt,
     5,
     {sizeof(int),
      _Neg,
      _Neg,
      sizeof(RSA),
      sizeof(int),
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_LEN,
      S_VARLEN_I | _RAND,
      S_VARLEN_O | _RAND,
      S_FIXLEN_IN | _RAND,
      S_FIXLEN_IN | _RAND,
      0,
      0,
      0,
      0}},
    //===  int RSA_private_encrypt(int flen, unsigned char *from,unsigned char
    //*to, RSA *rsa,int padding);
    {"RSA_private_encrypt",
     e_RSA_private_encrypt,
     5,
     {sizeof(int),
      _Neg,
      _Neg,
      sizeof(RSA),
      sizeof(int),
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_LEN,
      S_VARLEN_I | _RAND,
      S_VARLEN_O | _RAND,
      S_FIXLEN_IN | _RAND,
      S_FIXLEN_IN | _RAND,
      0,
      0,
      0,
      0}},
    //=== int RSA_public_decrypt(int flen, unsigned char *from, unsigned char
    //*to, RSA *rsa,int padding);
    {"RSA_public_decrypt",
     e_RSA_public_decrypt,
     5,
     {sizeof(int),
      _Neg,
      _Neg,
      sizeof(RSA),
      sizeof(int),
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_LEN,
      S_VARLEN_I | _RAND,
      S_VARLEN_O | _RAND,
      S_FIXLEN_IN | _RAND,
      S_FIXLEN_IN | _RAND,
      0,
      0,
      0,
      0}},
    //
    {"RSA_private_decrypt",
     e_RSA_private_decrypt,
     5,
     {sizeof(int),
      _Neg,
      _Neg,
      sizeof(RSA),
      sizeof(int),
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_LEN,
      S_VARLEN_I | _RAND,
      S_VARLEN_O | _RAND,
      S_FIXLEN_IN | _RAND,
      S_FIXLEN_IN | _RAND,
      0,
      0,
      0,
      0}},

};

t_openssl_schema* get_asym_schema()
{
    return _openssl_asym;
}

uint get_asym_schema_length()
{
    return sizeof(_openssl_asym) / sizeof(_openssl_asym[0]);
}

class CSchemaChecker_Asym : public CSchemaChecker
{
  public:
    CSchemaChecker_Asym(t_openssl_schema* schema, uint schema_size)
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

void CSchemaChecker_Asym::OverideRandomizedValue(
    openssl_api_id id,
    uint param_no,
    uint64_t type,
    uint origin,
    uint8_t* buf,
    uint buflen)
{
    if (id == e_RSA_generate_key_ex && param_no == 1)
    {
        uint v = *(uint*)buf;
        v = v % 5000;
        *(uint*)buf = v;
    }
    else // call default implementation
        CSchemaChecker::OverideRandomizedValue(
            id, param_no, type, origin, buf, buflen);
}

oe_result_t asymmetric_encryption_test_group(oe_enclave_t* enclave)
{
    oe_result_t result;
    int retval;
    uint num_apis = get_asym_schema_length();
    t_openssl_schema* schema = get_asym_schema();
    CSchemaChecker_Asym* checker = new CSchemaChecker_Asym(schema, num_apis);
    printf("total test number: %u\n", num_apis);
    for (int i = 0; i < (int)num_apis; i++)
    {
        checker->SetupParams((schema + i)->id, (uint32_t)i);
        printf("Test case: %s\tstarts \n", (schema + i)->api_name);
        result = ecall_asym_tests(enclave, &retval, (void*)(&(checker->m_p1)));
        OE_TEST(result == OE_OK);
        OE_TEST(retval >= 0);
        printf("Test case: %s\tends \n", (schema + i)->api_name);
    }
    return OE_OK;
}
