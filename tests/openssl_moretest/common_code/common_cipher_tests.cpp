// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include_openssl.h"

#include "openssl_schema.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

const EVP_MD* some_EVP_sha(unsigned char c);

static const EVP_CIPHER* some_EVP_cipher(unsigned int c)
{
    c &= 0x7;
    switch (c)
    {
        case 0:
            return EVP_aes_128_gcm();
        case 1:
            return EVP_aes_192_gcm();
        case 2:
            return EVP_aes_256_gcm();
        case 3:
            return EVP_aes_128_cbc();
        case 4:
            return EVP_aes_192_cbc();
        case 5:
        default:
            return EVP_aes_256_cbc();
            break;
    }
    return NULL;
}

static void init_cipher_ctx(EVP_CIPHER_CTX* ctx)
{
    char* p = (char*)ctx;
    memset(p, 0, sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
}

int common_symmetric_encryption_tests_internal(void* buf)
{
    openssl_api_param* p = (openssl_api_param*)buf;
    int ret = 0;
    switch (p->id)
    {
        case e_EVP_CipherInit_ex:
        {
            EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)p->p[0];
            unsigned char c = *(unsigned char*)(p->p[1]);
            uint8_t* key = (uint8_t*)(p->p[2]);
            uint8_t* ivec = (uint8_t*)p->p[3];
            int enc = *((int*)p->p[4]);
            const EVP_CIPHER* cipher;

            cipher = some_EVP_cipher(c);
            init_cipher_ctx(ctx);

            if (enc % 3 == 0)
                enc = 1; // encryption mode
            else if (enc % 3 == 1)
                enc = 0; // decryption mode
            else
                enc = -1; // without changing

            ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, ivec, enc);
        }
        break;
        case e_EVP_CipherUpdate:
        {
            EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)p->p[0];
            unsigned char c = *(unsigned char*)(p->p[1]);
            const EVP_CIPHER* cipher;
            uint8_t* key = (uint8_t*)(p->p[2]);
            uint8_t* ivec = (uint8_t*)p->p[3];
            int enc = *((int*)p->p[4]);

            cipher = some_EVP_cipher(c);
            init_cipher_ctx(ctx);
            if (enc % 3 == 0)
                enc = 1;
            else if (enc % 3 == 1)
                enc = 0;
            else
                enc = -1;

            ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, ivec, enc);
            if (ret == 1)
            {
                uint8_t* outBuf = (uint8_t*)p->p[5];
                uint8_t* inBuf = (uint8_t*)p->p[7];
                ret = EVP_CipherUpdate(
                    ctx, outBuf, (int*)&(p->p[6]), inBuf, 1024);
            }
        }
        break;
        case e_EVP_CipherFinal_ex:
        {
            EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)p->p[0];
            unsigned char c = *(unsigned char*)(p->p[1]);
            const EVP_CIPHER* cipher;
            uint8_t* key = (uint8_t*)(p->p[2]);
            uint8_t* ivec = (uint8_t*)p->p[3];
            int enc = 1; // must encrypt for final

            cipher = some_EVP_cipher(c);
            init_cipher_ctx(ctx);

            ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, ivec, enc);
            if (ret == 1)
            {
                uint8_t* outBuf = (uint8_t*)p->p[4];
                uint8_t* inBuf = (uint8_t*)p->p[6];
                ret = EVP_CipherUpdate(
                    ctx, outBuf, (int*)&(p->p[5]), inBuf, 1024);
                if (ret == 1)
                {
                    ret = EVP_CipherFinal_ex(ctx, outBuf, (int*)&(p->p[5]));
                }
            }
            break;
        }

        case e_HMAC:
        {
            HMAC_CTX* pctx;
            pctx = HMAC_CTX_new();

            char* data = p->p[2];
            char* key = p->p[0];
            unsigned char* result = (unsigned char*)p->p[3];
            unsigned int len = _ELLEPH;
            size_t key_len = (size_t)(p->p[1]);
            unsigned char ch = *(unsigned char*)&(p->p[0]);

            // Using sha1 hash engine here.
            // You may use other hash engines. e.g EVP_md5(), EVP_sha224,
            // EVP_sha512, etc
            if (HMAC_Init_ex(pctx, key, (int)key_len, some_EVP_sha(ch), NULL))
            {
                ret = 1;
                goto hmac_end;
            }
            if (HMAC_Update(pctx, (unsigned char*)data, _ELLEPH))
            {
                ret = 1;
                goto hmac_end;
            }
            if (HMAC_Final(pctx, result, &len))
            {
                ret = 1;
                goto hmac_end;
            }
        hmac_end:

            HMAC_CTX_free(pctx);

            break;
        }

        default:
            ret = -1;
            break;
    };
    return ret;
}

static int Dummy_func()
{
    if (0)
        throw "force the compiler not to optimize out the catch";
    return 1;
}

int common_symmetric_encryption_tests(void* buf)
{
    int ret = 0;

    try
    {
        Dummy_func(); // this is necessary to force the compiler not to optimize
                      // out the catch statement below
        ret = common_symmetric_encryption_tests_internal(buf);
    }
    catch (...)
    {
        ret = -1;
    }
    return ret;
}
