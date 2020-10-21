// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include "openssl/e_os2.h"
#include "openssl/sha.h"

#include "openssl_schema.h"

int EVP_PKEY_assign_test(openssl_api_param* param)
{
    int ret = 0;
    int key_type = *(int*)(param->p[0]);
    EVP_PKEY* pkey = EVP_PKEY_new();
    void* key = NULL;

    switch (key_type)
    {
        case 0:
        case 1:
            break;
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
            key = DSA_new();
            DSA_generate_parameters_ex(
                (DSA*)key, 2048, NULL, 0, NULL, NULL, NULL);
            if (DSA_generate_key((DSA*)key) != 1)
                ret = -1;
            break;
        case 7:
            printf("DH_generate_parameters API obsoleted\n");
            break;
        case 8:
            key = EC_KEY_new();
            EC_KEY_generate_key((EC_KEY*)key);
            break;
    }

    if (!key || !pkey)
    {
        ret = -1;
        goto out;
    }

    switch (key_type)
    {
        case 0: // RSA
            if (EVP_PKEY_assign(pkey, EVP_PKEY_RSA, key) == 0)
                ret = -1;
            break;
        case 1: // RSA2
            if (EVP_PKEY_assign(pkey, EVP_PKEY_RSA2, key) == 0)
                ret = -1;
            break;
        case 2: // DSA
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DSA, key) == 0)
                ret = -1;
            break;
        case 3: // DSA1
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DSA1, key) == 0)
                ret = -1;
            break;
        case 4: // DSA2
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DSA2, key) == 0)
                ret = -1;
            break;
        case 5: // DSA3
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DSA3, key) == 0)
                ret = -1;
            break;
        case 6: // DSA4
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DSA4, key) == 0)
                ret = -1;
            break;
        case 7: // DH
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DH, key) == 0)
                ret = -1;
            break;
        case 8: // EC
            if (EVP_PKEY_assign(pkey, EVP_PKEY_EC, key) == 0)
                ret = -1;
            break;
    }

out:
    if (pkey)
        EVP_PKEY_free(pkey);

    return ret;
}

int common_keygen_tests(void* buf)
{
    openssl_api_param* p = (openssl_api_param*)buf;
    int ret = 0;

    try
    {
        switch (p->id)
        {
            case e_EVP_PKEY_assign:
                ret = EVP_PKEY_assign_test(p);
                break;

            default:
                throw "unexpected api";
                ret = -1;
                break;
        };
    }
    catch (char* msg)
    {
        ret = -1;
    }

    return ret;
}
