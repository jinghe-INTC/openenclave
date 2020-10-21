// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include_openssl.h"
#include "openssl_schema.h"

static int to_nid(int num)
{
    int loop = 0;

    num &= 0x3ff;
    while (!OBJ_nid2sn(num))
    {
        num--;
        num &= 0x3ff;
        loop++;
        if (loop >= 500)
            return -1;
    }

    return num;
}

static const int curve_nids[] = {
    NID_secp112r1,
    NID_secp112r2,
    NID_secp128r1,
    NID_secp128r2,
    NID_secp160k1,
    NID_secp160r1,
    NID_secp160r2,
    NID_secp192k1,
    NID_secp224k1,
    NID_secp256k1,
    NID_secp384r1,
    NID_secp521r1,
    NID_X9_62_prime192v1,
    NID_X9_62_prime192v2,
    NID_X9_62_prime192v3,
    NID_X9_62_prime239v1,
    NID_X9_62_prime239v2,
    NID_X9_62_prime239v3,
    NID_X9_62_prime256v1,
    NID_wap_wsg_idm_ecid_wtls6,
    NID_wap_wsg_idm_ecid_wtls7,
    NID_wap_wsg_idm_ecid_wtls8,
    NID_wap_wsg_idm_ecid_wtls9,
    NID_wap_wsg_idm_ecid_wtls12,
};

static int create_verify_signature(
    const unsigned char* hash,
    size_t len,
    int nid,
    bool asn1_flag)
{
    int ret = 0;
    ECDSA_SIG* signature = NULL;
    EC_KEY* eckey;
    int verify_status;

    nid = (int)((uint64_t)nid % sizeof(curve_nids) / sizeof(curve_nids[0]));
    nid = curve_nids[nid];
    eckey = EC_KEY_new_by_curve_name(nid);
    if (!eckey)
    {
        printf("Failed to create new EC Key\n");
        return 1;
    }

    if (asn1_flag)
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    int gen_status = EC_KEY_generate_key(eckey);
    if (1 != gen_status)
    {
        printf("Failed to generate EC Key\n");
        ret = 1;
        goto Exit;
    }

    signature = ECDSA_do_sign(hash, (int)len, eckey);
    if (!signature)
    {
        printf("Failed to generate EC Signature\n");
        ret = 1;
        goto Exit;
    }

    verify_status = ECDSA_do_verify(hash, (int)len, signature, eckey);
    if (1 != verify_status)
    {
        printf("Failed to verify EC Signature\n");
        ret = 1;
    }

Exit:

    if (eckey)
        EC_KEY_free(eckey);
    if (signature)
        ECDSA_SIG_free(signature);
    return ret;
}

static void Reset_EVP_MD_CTX(EVP_MD_CTX* p)
{
    memset((char*)p, 0, sizeof(EVP_MD_CTX));
}

static int _sign(EVP_PKEY* pk, unsigned char* s, unsigned int len)
{
    const EVP_MD* emd;
    EVP_MD_CTX ctx;
    int ret = 0;

    emd = EVP_sha512();
    Reset_EVP_MD_CTX(&ctx);
    ret = EVP_SignInit_ex(&ctx, emd, NULL);
    if (1 != ret)
    {
        printf("EVP_SignInit_ex failed.\n");
        return 1;
    }

    ret = EVP_SignUpdate(&ctx, "hello hello hello hello hello hello", 20);
    if (1 != ret)
    {
        printf("EVP_SignUpdate failed.\n");
        return 1;
    }

    ret = EVP_SignFinal(&ctx, s, &len, pk);
    if (1 != ret)
    {
        printf("EVP_SignFinal failed.\n");
        return 1;
    }

    return 0;
}

static int _verify(EVP_PKEY* pk, unsigned char* s, unsigned int len)
{
    const EVP_MD* emd;
    EVP_MD_CTX ctx;
    int ret = 0;

    emd = EVP_sha512();
    Reset_EVP_MD_CTX(&ctx);
    ret = EVP_VerifyInit_ex(&ctx, emd, NULL);
    if (1 != ret)
    {
        printf("EVP_VerifyInit_ex failed.\n");
        return 1;
    }

    ret = EVP_VerifyUpdate(&ctx, "hello hello hello hello hello hello", 20);
    if (1 != ret)
    {
        printf("EVP_VerifyUpdate failed.\n");
        return 1;
    }

    ret = EVP_VerifyFinal(&ctx, s, len, pk);
    if (1 != ret)
    {
        printf("EVP_VerifyFinal failed.\n");
        return 1;
    }

    return 0;
}

int common_akamai_tests(void* buf)
{
    openssl_api_param* p = (openssl_api_param*)buf;
    int ret = 0;
    int n;
    const unsigned char hash[] = "c7fbca202a95a570285e3d700eb04ca2";
    switch (p->id)
    {
        case e_EC_Key:
            /*
             * Includes:
             *		EC_key_new_by_curve_name,
             *		EC_KEY_free,
             *		EC_KEY_new,
             *		EC_KEY_set_asn1_flag,
             */
            n = *((int*)(p->p[0]));

            ret = create_verify_signature(hash, sizeof(hash) - 1, n, false);
            if (ret)
                break;

            ret = create_verify_signature(hash, sizeof(hash) - 1, n, true);
            break;

        case e_OBJ_txt2nid:
        {
            /*
             * OBJ_txt2nid
             * OBJ_nid2sn
             */

            const char* sn;
            int* q = (int*)(p->p[1]);

            n = *((int*)(p->p[0]));
            n = to_nid(n);
            sn = OBJ_nid2sn(n);
            if (sn)
            {
                *q = OBJ_txt2nid(sn);
                memcpy(p->p[2], sn, strlen(sn));
            }
            break;
        }
        case e_i2d_PrivateKey:
            /*
             * i2d_PrivateKey
             * i2d_PublicKey
             *
             * RSA_generate_key
             * EVP_PKEY_assign_RSA
             * EVP_PKEY_new
             * d2i_PublicKey
             * d2i_AutoPrivateKey
             * EVP_PKEY_size
             */
            {
                int ret = 0;
                EVP_PKEY *pKey = NULL, *pPrivKey = NULL, *pPubKey = NULL;
                unsigned int sig_len;
                unsigned char* sig = NULL;
                int pkeyLen = 2048;
                BIGNUM* bn = NULL;
                bn = BN_new();

                if (!bn)
                {
                    printf("failed\n");
                    break;
                }
                RSA* pRSA = RSA_new();
                if (!pRSA)
                {
                    printf("failed\n");
                    break;
                }
                ret = BN_set_word(bn, RSA_3);
                if (ret != 1)
                {
                    printf(
                        "failed and "
                        "returned %d\n",
                        ret);
                    break;
                }

                ret = RSA_generate_key_ex(pRSA, (int32_t)pkeyLen, bn, NULL);

                if (ret == 0)
                {
                    printf(
                        "in common_asym_tests() - create_key() - "
                        "RSA_generate_key_ex() "
                        "failed and returned %d\n",
                        ret);
                    break;
                }

                if (!pRSA)
                {
                    printf("Failed to RSA_generate_key_ex\n");
                    ret = 1;
                    break;
                }

                pKey = EVP_PKEY_new();
                if (!pKey)
                {
                    printf("Failed to EVP_PKEY_new\n");
                    ret = 1;
                    break;
                }

                if (!EVP_PKEY_assign_RSA(pKey, pRSA) ||
                    RSA_check_key(pRSA) <= 0)
                {
                    /* pKey owns pRSA from now */
                    printf("RSA_check_key failed.\n");
                    EVP_PKEY_free(pKey);
                    pKey = NULL;
                    ret = 1;
                    break;
                }

                // Extract the private key
                unsigned char *ucBuf, *uctempBuf;
                pkeyLen = i2d_PrivateKey(pKey, NULL);
                ucBuf = new unsigned char[(uint64_t)pkeyLen + 1];
                uctempBuf = ucBuf;
                i2d_PrivateKey(pKey, &uctempBuf);
                uctempBuf = ucBuf;
                pPrivKey = d2i_AutoPrivateKey(
                    NULL, (const unsigned char**)&uctempBuf, pkeyLen);
                if (!pPrivKey)
                {
                    printf("d2i_AutoPrivateKey failed.\n");
                    ret = 1;
                    goto out;
                }

                //
                // sign using the private key
                sig_len = (unsigned int)EVP_PKEY_size(pPrivKey);
                sig = new unsigned char[sig_len];

                ret = _sign(pPrivKey, sig, sig_len);
                if (ret)
                    goto out;

                // Extract the public key
                pkeyLen = i2d_PublicKey(pKey, NULL);
                delete[] ucBuf;
                ucBuf = new unsigned char[(unsigned int)pkeyLen + 1];
                uctempBuf = ucBuf;
                i2d_PublicKey(pKey, &uctempBuf);

                uctempBuf = ucBuf;
                pPubKey = d2i_PublicKey(
                    EVP_PKEY_RSA,
                    NULL,
                    (const unsigned char**)&uctempBuf,
                    pkeyLen);
                if (!pPubKey)
                {
                    printf("d2i_PublicKey failed.\n");
                    ret = 1;
                    goto out;
                }
                // verify using the public key
                ret = _verify(pPubKey, sig, sig_len);
                if (ret)
                    goto out;

            out:
                if (sig)
                    delete[] sig;

                if (pPrivKey)
                    EVP_PKEY_free(pPrivKey);
                if (pPubKey)
                    EVP_PKEY_free(pPubKey);
                if (pKey)
                    EVP_PKEY_free(pKey);
                if (ret)
                    *((char*)p->p[0]) = 0x1;

                break;
            }

        default:
            throw "unexpected api";
            break;
    };

    if (ret)
    {
        long err = (long)ERR_get_error();
        printf(
            "ERR_get_error=0x%lx string=%s\n",
            err,
            ERR_error_string((uint64_t)err, NULL));
    }

    return ret;
}
