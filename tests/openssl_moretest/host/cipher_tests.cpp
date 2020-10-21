// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <openenclave/internal/tests.h>
#include "CSchema_checker.h"
#include "openssl_moretest_u.h"

t_openssl_schema _openssl_cipher[] = {
    {"EVP_CipherInit_ex",
     e_EVP_CipherInit_ex,
     5,
     {sizeof(EVP_CIPHER_CTX),
      sizeof(EVP_CIPHER),
      EVP_MAX_KEY_LENGTH,
      EVP_MAX_IV_LENGTH,
      sizeof(int),
      _Neg,
      _Neg,
      _Neg,
      _Neg},
     {S_FIXLEN_IO | S_RAND | S_CMP_EVP_CIPHER_CTX,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      0,
      0,
      0,
      0}},
    {"EVP_CipherUpdate",
     e_EVP_CipherUpdate,
     8,
     {sizeof(EVP_CIPHER_CTX),
      sizeof(EVP_CIPHER),
      EVP_MAX_KEY_LENGTH,
      EVP_MAX_IV_LENGTH,
      sizeof(int),
      4096,
      sizeof(int),
      1024,
      _Neg},
     {S_FIXLEN_IO | S_RAND | S_CMP_EVP_CIPHER_CTX,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO,
      S_LEN,
      S_FIXLEN_IO | S_RAND,
      0}},
    {"EVP_CipherFinal_ex",
     e_EVP_CipherFinal_ex,
     7,
     {sizeof(EVP_CIPHER_CTX),
      sizeof(EVP_CIPHER),
      EVP_MAX_KEY_LENGTH,
      EVP_MAX_IV_LENGTH,
      4096,
      sizeof(int),
      1024,
      _Neg},
     {S_FIXLEN_IO | S_RAND | S_CMP_EVP_CIPHER_CTX,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      S_LEN,
      S_FIXLEN_IO | S_RAND,
      0}},
    {"HMAC",
     e_HMAC,
     4,
     {_Neg, sizeof(size_t), _ELLEPH, _ELLEPH, _Neg, _Neg, _Neg, _Neg, _Neg},
     {S_VARLEN_I | S_RAND,
      S_LEN,
      S_FIXLEN_IO | S_RAND,
      S_FIXLEN_IO | S_RAND,
      0,
      0,
      0,
      0,
      0}},
};

t_openssl_schema* get_cipher_schema()
{
    return _openssl_cipher;
}

uint get_cipher_schema_length()
{
    return sizeof(_openssl_cipher) / sizeof(_openssl_cipher[0]);
}
class CSchemaChecker_Cipher : public CSchemaChecker
{
  public:
    CSchemaChecker_Cipher(t_openssl_schema* schema, uint schema_size)
        : CSchemaChecker(schema, schema_size)
    {
    }
};
oe_result_t ecall_schema_run_symmetric_encryption(oe_enclave_t* enclave)
{
    oe_result_t result;
    int retval;
    uint num_apis = get_cipher_schema_length();
    t_openssl_schema* schema = get_cipher_schema();
    CSchemaChecker_Cipher* checker =
        new CSchemaChecker_Cipher(schema, num_apis);
    printf("total test number: %u\n", num_apis);

    for (int i = 0; i < (int)num_apis; i++)
    {
        checker->SetupParams((schema + i)->id, (uint32_t)i);
        printf("Test case: %s\tstarts \n", (schema + i)->api_name);
        result = ecall_schema_run_symmetric_encryption(
            enclave, &retval, (void*)(&(checker->m_p1)));
        OE_TEST(result == OE_OK);
        OE_TEST(retval >= 0);
        printf("Test case: %s\tends \n", (schema + i)->api_name);
    }
    return OE_OK;
}
