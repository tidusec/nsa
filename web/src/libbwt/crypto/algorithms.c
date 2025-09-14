#include "algorithms.h"

#include <errno.h>

#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>

static inline EVP_PKEY* pkey_from_key(const unsigned char* key, size_t key_len) {
    OSSL_DECODER_CTX* dctx;
    EVP_PKEY* pkey = nullptr;
    const char* format = nullptr;    /* any format */
    const char* structure = nullptr; /* any structure */
    const char* keytype = nullptr;   /* any key */

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format, structure, keytype,
        /*OSSL_KEYMGMT_SELECT_KEYPAIR*/0, nullptr, nullptr);

    if (dctx == nullptr) {
        return nullptr;
    }

    OSSL_DECODER_from_data(dctx, &key, &key_len);

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

int openssl_sign_sha_hmac(const AlgorithmHMAC alg_id,
                          unsigned char** result, size_t* result_size,
                          const unsigned char* data, const size_t data_size,
                          const unsigned char* key, const int key_size) {
    const EVP_MD* alg;

    *result = nullptr;

    switch (alg_id) {
        /* HMAC */
        case HS256: alg = EVP_sha256(); break;
        case HS384: alg = EVP_sha384(); break;
        case HS512: alg = EVP_sha512(); break;
        default: return EINVAL;
    }

    *result_size = 0;
    *result = malloc(EVP_MAX_MD_SIZE);
    if (*result == nullptr) {
        return ENOMEM;
    }

    // The cast is OK since size_t > unsigned int and the current value is 0
    if (HMAC(alg, key, key_size, data, data_size, *result, (unsigned int*) result_size) == nullptr) {
        *result_size = 0;
        *result = nullptr;
        free(*result);
        return EINVAL;
    }

    return 0;
}

bool openssl_verify_sha_hmac(const AlgorithmHMAC alg_id,
                             const unsigned char* signature, const size_t signature_size,
                             const unsigned char* data, const size_t data_size,
                             const unsigned char* key, const int key_size) {
    unsigned char* new_sig;
    size_t new_sig_size;

    if (openssl_sign_sha_hmac(alg_id, &new_sig, &new_sig_size, data, data_size, key, key_size) != 0) {
        // Operation failed, but nothing needs to be freed, so just return false
        return false;
    }

    const bool result = (signature_size == new_sig_size) &&
                        (CRYPTO_memcmp(new_sig, signature, signature_size) == 0);
    free(new_sig);
    return result;
}

int openssl_sign_sha_pem(const AlgorithmPEM alg_id,
                         unsigned char** result, size_t* result_size,
                         const unsigned char* data, const size_t data_size,
                         const unsigned char* key, const size_t key_size) {
    EVP_MD_CTX* mdctx = nullptr;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    EVP_PKEY* pkey;
    const EVP_MD* alg;
    int type;
    unsigned char* sig = nullptr;
    int ret = 0;
    size_t slen;

    switch (alg_id) {
        /* RSA */
        case RS256: alg = EVP_sha256(); type = EVP_PKEY_RSA; break;
        case RS384: alg = EVP_sha384(); type = EVP_PKEY_RSA; break;
        case RS512: alg = EVP_sha512(); type = EVP_PKEY_RSA; break;

        /* RSA-PSS */
        case PS256: alg = EVP_sha256(); type = EVP_PKEY_RSA_PSS; break;
        case PS384: alg = EVP_sha384(); type = EVP_PKEY_RSA_PSS; break;
        case PS512: alg = EVP_sha512(); type = EVP_PKEY_RSA_PSS; break;

        /* ECC */
        case ES256: alg = EVP_sha256(); type = EVP_PKEY_EC; break;
        case ES384: alg = EVP_sha384(); type = EVP_PKEY_EC; break;
        case ES512: alg = EVP_sha512(); type = EVP_PKEY_EC; break;

        default: return EINVAL;
    }

    pkey = pkey_from_key(key, key_size);
    if (pkey == nullptr) {
        ret = EINVAL;
        goto jwt_sign_sha_pem_done;
    }

    if (type != EVP_PKEY_id(pkey)) {
        ret = EINVAL;
        goto jwt_sign_sha_pem_done;
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr) {
        ret = ENOMEM;
        goto jwt_sign_sha_pem_done;
    }

    /* Initialize the DigestSign operation using alg */
    if (EVP_DigestSignInit(mdctx, &pkey_ctx, alg, nullptr, pkey) != 1) {
        ret = EINVAL;
        goto jwt_sign_sha_pem_done;
    }

    /* Required for RSA-PSS */
    if (type == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) < 0) {
            ret = EINVAL;
            goto jwt_sign_sha_pem_done;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) < 0) {
            ret = EINVAL;
            goto jwt_sign_sha_pem_done;
        }
    }

    /* Get the size of sig first */
    if (EVP_DigestSign(mdctx, nullptr, &slen, data, data_size) != 1) {
        ret = EINVAL;
        goto jwt_sign_sha_pem_done;
    }

    /* Allocate memory for signature based on returned size */
    sig = malloc(slen);
    if (sig == nullptr) {
        ret = ENOMEM;
        goto jwt_sign_sha_pem_done;
    }

    /* Actual signing */
    if (EVP_DigestSign(mdctx, sig, &slen, data, data_size) != 1) {
        ret = EINVAL;
        goto jwt_sign_sha_pem_done;
    }

    *result = sig;
    *result_size = slen;

    /* Avoid freeing *result at jwt_sign_sha_pem_done */
    sig = nullptr;

jwt_sign_sha_pem_done:
    free(sig);

    EVP_PKEY_free(pkey);
    //EVP_PKEY_CTX_free(pkey_ctx);

    EVP_MD_CTX_destroy(mdctx);

    return ret;
}

bool openssl_verify_sha_pem(const AlgorithmPEM alg_id,
                            const unsigned char* signature, const size_t signature_size,
                            const unsigned char* data, const size_t data_size,
                            const unsigned char* key, const size_t key_size) {
    bool ret = false;

    EVP_MD_CTX* mdctx = nullptr;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    EVP_PKEY* pkey;
    const EVP_MD* alg;
    int type;

    switch (alg_id) {
        /* RSA */
        case RS256: alg = EVP_sha256(); type = EVP_PKEY_RSA; break;
        case RS384: alg = EVP_sha384(); type = EVP_PKEY_RSA; break;
        case RS512: alg = EVP_sha512(); type = EVP_PKEY_RSA; break;

        /* RSA-PSS */
        case PS256: alg = EVP_sha256(); type = EVP_PKEY_RSA_PSS; break;
        case PS384: alg = EVP_sha384(); type = EVP_PKEY_RSA_PSS; break;
        case PS512: alg = EVP_sha512(); type = EVP_PKEY_RSA_PSS; break;

        /* ECC */
        case ES256: alg = EVP_sha256(); type = EVP_PKEY_EC; break;
        case ES384: alg = EVP_sha384(); type = EVP_PKEY_EC; break;
        case ES512: alg = EVP_sha512(); type = EVP_PKEY_EC; break;

        default: return EINVAL;
    }

    pkey = pkey_from_key(key, key_size);
    if (pkey == nullptr) {
        goto jwt_verify_sha_pem_done;
    }

    if (type != EVP_PKEY_id(pkey)) {
        goto jwt_verify_sha_pem_done;
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr) {
        goto jwt_verify_sha_pem_done;
    }

    /* Initialize the DigestVerify operation using alg */
    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, alg, nullptr, pkey) != 1) {
        goto jwt_verify_sha_pem_done;
    }

    if (type == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) < 0) {
            goto jwt_verify_sha_pem_done;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) < 0) {
            goto jwt_verify_sha_pem_done;
        }
    }

    /* One-shot update and verify */
    ret = (EVP_DigestVerify(mdctx, signature, signature_size, data, data_size) == 1);

jwt_verify_sha_pem_done:
    EVP_PKEY_free(pkey);
//    EVP_PKEY_CTX_free(pkey_ctx);

    EVP_MD_CTX_destroy(mdctx);

    return ret;
}