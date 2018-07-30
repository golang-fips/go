// This file contains RSA portability wrappers.
// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goboringcrypto.h"

// Only in BoringSSL.
int
_goboringcrypto_RSA_verify_raw(GO_RSA *rsa, size_t *out_len, uint8_t *out,
				 size_t max_out,
				 const uint8_t *in, size_t in_len, int padding)
{
  if (max_out < RSA_size(rsa)) {
    return 0;
  }
  int ret = RSA_public_decrypt (in_len, in, out, rsa, padding);
  if (ret <= 0) {
    return 0;
  }
  *out_len = ret;
  return 1;
}

// Only in BoringSSL.
int
 _goboringcrypto_RSA_generate_key_fips(GO_RSA *rsa, int size, GO_BN_GENCB *cb)
{
  // BoringSSL's RSA_generate_key_fips hard-codes e to 65537.
  BIGNUM *e = BN_new();
  if (e == NULL)
    return 0;
  int ret = BN_set_word(e, RSA_F4)
    && RSA_generate_key_ex(rsa, size, e, cb);
  BN_free(e);
  return ret;
}

// Only in BoringSSL.
int _goboringcrypto_RSA_sign_raw(GO_RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding) {
  if (max_out < RSA_size(rsa))
    return 0;
  int ret = RSA_private_encrypt (in_len, in, out, rsa, padding);
  if (ret <= 0)
    return 0;
  *out_len = ret;
  return 1;
}

int _goboringcrypto_RSA_sign_pss_mgf1(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                      const uint8_t *in, size_t in_len, const EVP_MD *md,
                      const EVP_MD *mgf1_md, int salt_len) {
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey;
	size_t siglen;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return 0;

	if (EVP_PKEY_set1_RSA(pkey, rsa) <= 0)
		return 0;
	
	ctx = EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
	if (!ctx)
		return 0;

	int ret = 0;

	if (EVP_PKEY_sign_init(ctx) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
		goto err;
	
	/* Determine buffer length */
	if (EVP_PKEY_sign(ctx, NULL, &siglen, in, in_len) <= 0)
		goto err;

	if (max_out < siglen)
		goto err;

	if (EVP_PKEY_sign(ctx, out, &siglen, in, in_len) <= 0)
		goto err;

	*out_len = siglen;
	ret = 1;

err:
	EVP_PKEY_CTX_free(ctx);

	return ret;
}

int _goboringcrypto_RSA_verify_pss_mgf1(RSA *rsa, const uint8_t *msg, size_t msg_len,
                        const EVP_MD *md, const EVP_MD *mgf1_md, int salt_len,
                        const uint8_t *sig, size_t sig_len) {
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey;

	int ret = 0;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return 0;

	if (EVP_PKEY_set1_RSA(pkey, rsa) <= 0)
		return 0;
	
	ctx = EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
	if (!ctx)
		return 0;

	if (EVP_PKEY_verify_init(ctx) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
		goto err;
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
		goto err;
	if (EVP_PKEY_verify(ctx, sig, sig_len, msg, msg_len) <= 0)
		goto err;

	ret = 1;

err:
	EVP_PKEY_CTX_free(ctx);

	return ret;
}
