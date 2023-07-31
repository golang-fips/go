// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goboringcrypto.h"

int
_goboringcrypto_ECDSA_sign(EVP_MD* md, const uint8_t *msg, size_t msgLen, uint8_t *sig, unsigned int *slen, GO_EC_KEY *eckey)
{
    int result;
    EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
    if (!key) {
        return 0;
    }
    if (!_goboringcrypto_EVP_PKEY_set1_EC_KEY(key, eckey)) {
        result = 0;
        goto err;
    }
    size_t _slen;
    result = _goboringcrypto_EVP_sign(md, NULL, msg, msgLen, sig, &_slen, key);
    *slen = _slen;
err:
    _goboringcrypto_EVP_PKEY_free(key);
    return result;
}

int
_goboringcrypto_ECDSA_verify(EVP_MD* md, const uint8_t *msg, size_t msgLen, const uint8_t *sig, unsigned int slen, GO_EC_KEY *eckey)
{

    int result;
    EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
    if (!key) {
        return 0;
    }
    if (!_goboringcrypto_EVP_PKEY_set1_EC_KEY(key, eckey)) {
        result = 0;
        goto err;
    }

    result = _goboringcrypto_EVP_verify(md, NULL, msg, msgLen, sig, slen, key);

err:
    _goboringcrypto_EVP_PKEY_free(key);
    return result;
}
