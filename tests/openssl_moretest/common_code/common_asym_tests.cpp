// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include_openssl.h"
#include "openssl/e_os2.h"
#include "openssl_schema.h"

#define CHECK_RSA_ERR(func)                                                    \
    if (ret == -1)                                                             \
    {                                                                          \
        char errbuf[200];                                                      \
        ERR_load_crypto_strings();                                             \
        int err = (int32_t)ERR_get_error();                                    \
        ERR_error_string((uint64_t)err, errbuf);                               \
        printf("in common_asym_tests() %s() failed (ERR=%s)\n", func, errbuf); \
    }

static RSA* create_key(BIGNUM*& bn, uint keylength)
{
    int ret = 0;
    bn = BN_new();
    if (!bn)
    {
        printf("in common_asym_tests() - create_key() - BN_new() failed\n");
        return NULL;
    }
    RSA* rsa = RSA_new();
    if (!rsa)
    {
        printf("in common_asym_tests() - create_key() - RSA_new() failed\n");
        goto err;
    }
    ret = BN_set_word(bn, RSA_F4);
    if (ret != 1)
    {
        printf(
            "in common_asym_tests() - create_key() - BN_set_word() failed and "
            "returned %d\n",
            ret);
        goto err;
    }
    if (keylength > 3000)
        printf(
            "in common_asym_tests() - create_key() - before "
            "RSA_generate_key_ex() keylength=%d\n",
            keylength);
    ret = RSA_generate_key_ex(rsa, (int32_t)keylength, bn, NULL);
    if (ret == 0)
    {
        printf(
            "in common_asym_tests() - create_key() - RSA_generate_key_ex() "
            "failed and returned %d\n",
            ret);
        goto err;
    }
    return rsa;
err:
    if (bn)
        BN_free(bn);
    if (rsa)
        RSA_free(rsa);
    return NULL;
}

void my_strcpy(char* target, const char* source)
{
    int i = 0;
    do
    {
        target[i] = source[i];
    } while (source[i++] != 0);
}

int Do_encrypt(
    int mode,
    int tlen,
    unsigned char* from,
    unsigned char* to,
    RSA* rsa,
    int padding,
    char* func_str,
    int* encrypted_size)
{
    int len = tlen;
    int idx = 0;
    int idx1 = 0;
    int max_msg_size = 214; // for keysize of 2048
    int ret = -1;

    char rand_buff[16];
    // RAND_seed(rand_buff, 16);
    memcpy(
        rand_buff, from, 16); // make random see the same for ENCLAVE and native
    while (len > 0)
    {
        int sz = len;
        if (sz > max_msg_size)
            sz = max_msg_size;
        if ((mode == 0) || (mode == 3))
            ret = RSA_public_encrypt(
                sz,
                &from[idx],
                (unsigned char*)&to[idx1],
                rsa,
                padding); // RSA_NO_PADDING,RSA_PKCS1_PADDING,RSA_PKCS1_OAEP_PADDING
        else if ((mode == 1) || (mode == 2))
            ret = RSA_private_encrypt(
                sz,
                &from[idx],
                (unsigned char*)&to[idx1],
                rsa,
                padding); // RSA_NO_PADDING,RSA_PKCS1_PADDING,RSA_PKCS1_OAEP_PADDING
        CHECK_RSA_ERR(func_str);
        if (ret == -1)
            break;
        len -= sz;
        idx += sz;
        idx1 += ret;
    }
    *encrypted_size = idx1;
    printf(
        "public_encrypt() (func = %s) ret=%d idx1=%d\n", func_str, ret, idx1);
    return ret;
}

int test_RSA_generate_key_ex(openssl_api_param* p)
{
    int ret = 0;
    BIGNUM* bn = NULL;
    uint keylength;
    RSA* rsa;
    // int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    //    rsa should be created with : RSA_new();
    //     bits is usually 1024/2048/4096
    //     e should be created with BN_new();
    //     cb can be NULL
    //
    //   Randomize
    //		* keylength
    //
    //   ENCLAVE/NATIVE compare
    //     * nothing
    // we limit it up to 5000 in OverideRandomizedValue()
    // since longer keys generation take a long time
    keylength = *(uint*)(p->p[1]);
    rsa = create_key(bn, keylength);
    if (rsa)
    {
        /*printf(
            "in common_asym_tests() calling RSA_generate_key_ex() with "
            "keylength=%d is OK\n",
            keylength);*/
        BN_free(bn);
        RSA_free(rsa);
        ret = 1;
    }
    return ret;
}

int Do_decrypt(
    int mode,
    int text_len,
    unsigned char* from,
    int64_t encrypted_size,
    unsigned char* encrypted_buf,
    RSA* rsa,
    int padding,
    char* func_str)
{
    char* text3 = (char*)malloc((uint64_t)(text_len + 10));
    if (!text3)
    {
        printf(
            "error allocating %d bytes in asym_tests - Do_decrypt()\n",
            text_len + 10);
        return -1;
    }
    // Decrypt it
    int len = text_len;
    int idx = 0;
    int idx1 = 0;
    int ret = 0;
    int first_ret = 256; // for keysize = 2048
    while (len > 0)
    {
        int sz = first_ret;
        if (sz > (int)(encrypted_size - idx))
            sz = (int)(encrypted_size - idx);
        // char c = text1[idx+sz];
        // text1[idx+sz] = 0;
        if (mode == 3)
            ret = RSA_private_decrypt(
                sz,
                (unsigned char*)&encrypted_buf[idx],
                (unsigned char*)&text3[idx1],
                rsa,
                padding);
        else if (mode == 2)
            ret = RSA_public_decrypt(
                sz,
                (unsigned char*)&encrypted_buf[idx],
                (unsigned char*)&text3[idx1],
                rsa,
                padding);
        CHECK_RSA_ERR(func_str);
        if (ret == -1)
            break;
        // text1[idx+sz] = c;
        len -= ret;
        idx += sz;
        idx1 += ret;
    }
    printf("After %s ret=%d idx=%d idx1=%d\n", func_str, ret, idx, idx1);
    ret = memcmp(from, text3, (uint64_t)text_len);
    if (ret)
        printf("After %s memcmp FAILED. ret=%d\n", func_str, ret);
    else
        printf("After %s memcmp OK. ret=%d\n", func_str, ret);
    free(text3);
    return ret;
}

int test_RSA_private_public_decrypt(
    int mode,
    openssl_api_param* p,
    RSA* rsa,
    int encrypted_size,
    int padding,
    unsigned char* encrypted_buf)
{
    int ret = 0;
    char func_str[30];
    if (mode == 2)
        my_strcpy(func_str, "RSA_public_decrypt");
    else if (mode == 3)
        my_strcpy(func_str, "RSA_private_decrypt");
    int flen = *(int*)&(p->p[0]);
    unsigned char* from = (unsigned char*)(p->p[1]);
    ret = Do_decrypt(
        mode,
        flen,
        from,
        encrypted_size,
        encrypted_buf,
        rsa,
        padding,
        func_str);
    return ret;
}

int test_RSA_private_public_encrypt(int mode, openssl_api_param* p)
{
    int ret = 0;
    char func_str[30];
    int padding = *(int*)(p->p[1]);
    // RSA_private_encrypt fails if using RSA_PKCS1_OAEP_PADDING
    // RSA_public_encrypt     ok if using RSA_PKCS1_OAEP_PADDING
    if ((mode == 0) || (mode == 3))
    {
        my_strcpy(func_str, "RSA_public_encrypt");
        if (padding % 2 == 0)
            padding = RSA_PKCS1_PADDING;
        else
            padding = RSA_PKCS1_OAEP_PADDING;
    }
    else if ((mode == 1) || (mode == 2))
    {
        my_strcpy(func_str, "RSA_private_encrypt");
        padding = RSA_PKCS1_PADDING;
    }

    //
    //   Randomize
    //		* input/output length
    //		* input/output buffers
    //
    //   keylength is fixed 2048
    //
    //   ENCLAVE/NATIVE compare
    //     * input buffers
    //     * output buffers not set since they cannot be the same (using
    //     different RSA keys)

    //  int RSA_public_encrypt(int flen, unsigned char *from,unsigned char *to,
    //  RSA *rsa, int padding);
    int flen = *(int*)&(p->p[0]);
    unsigned char* from = (unsigned char*)(p->p[1]);
    BIGNUM* bn = NULL;
    uint keylength = 2048; // note - changing this requires that you change
                           // max_msg_size below and in public_encrypt() above
    RSA* rsa = create_key(bn, keylength);
    if (!rsa)
        ret = -1;
    else
    {
        int encrypted_size = 0;
        // printf("in common_asym_tests() %s flen=%d padding=%d\n", func_str,
        // flen, padding);
        // 3rd parameter, output length, is not the same as the input length in
        // this case it should be larger
        uint inplen = (uint32_t)flen;
        uint max_msg_size = 214; // for fixed keysize of 2048
        uint out_size = 256 * (inplen / max_msg_size + 1);
        unsigned char* to1 = (unsigned char*)malloc(out_size + 10);
        if (!to1)
        {
            printf("error allocating to1 in %s size=%d\n", func_str, out_size);
            ret = -1;
        }
        else
        {
            ret = Do_encrypt(
                mode,
                (int)flen,
                from,
                to1,
                rsa,
                padding,
                func_str,
                &encrypted_size);

            // ret = RSA_public_encrypt(flen, from,to, rsa, padding);
            //
            // cannot copy output back
            //   since ENCLAVE is not the same as the NATIVE, they use different
            //   keys! and RSA cannot be copied from ENCLAVE to native. Search
            //   for  NOT_WORKING_SAD_FACE to see my attempt
            //
            // memcpy(to,to1,flen);

            if (ret > 0 && mode > 1)
            { // decryption
                ret = test_RSA_private_public_decrypt(
                    mode, p, rsa, encrypted_size, padding, to1);
            }
            free(to1);
        }
        BN_free(bn);
        RSA_free(rsa);
    }
    return ret;
}

int common_asym_tests(void* buf)
{
    openssl_api_param* p = (openssl_api_param*)buf;
    printf("test id: %d\n", p->id);
    int ret = 0;

    try
    {
        switch (p->id)
        {
            /*
                    RSA
            */
            case e_RSA_generate_key_ex:
                ret = test_RSA_generate_key_ex(p);
                break;
            case e_RSA_generate_key:
                printf("RSA_generate_key API obsoleted\n");
                ret = 1;
                break;
            case e_RSA_public_encrypt:
                ret = test_RSA_private_public_encrypt(0, p);
                break;
            case e_RSA_private_encrypt:
                ret = test_RSA_private_public_encrypt(1, p);
                break;
            case e_RSA_public_decrypt:
                ret = test_RSA_private_public_encrypt(
                    2, p); // will do encryption and then decryption
                break;
            case e_RSA_private_decrypt:
                ret = test_RSA_private_public_encrypt(
                    3, p); // will do encryption and then decryption
                break;
            default:
                throw "unexpected api";
                ret = -1;
                break;
        };
    }
    catch (char* msg)
    {
        printf("common_asym: exception caught(): msg=%s \n", msg);
    }
    printf("test id: %d end\n", p->id);
    return ret;
}
