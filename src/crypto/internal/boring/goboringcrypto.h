// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This header file describes the BoringCrypto ABI as built for use in Go.
// The BoringCrypto build for Go (which generates goboringcrypto_*.syso)
// takes the standard libcrypto.a from BoringCrypto and adds the prefix
// _goboringcrypto_ to every symbol, to avoid possible conflicts with
// code wrapping a different BoringCrypto or OpenSSL.
//
// To make this header standalone (so that building Go does not require
// having a full set of BoringCrypto headers), the struct details are not here.
// Instead, while building the syso, we compile and run a C++ program
// that checks that the sizes match. The program also checks (during compilation)
// that all the function prototypes match the BoringCrypto equivalents.
// The generation of the checking program depends on the declaration
// forms used below (one line for most, multiline for enums).

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t

#include <openssl/crypto.h>

static inline int
_goboringcrypto_FIPS_mode(void)
{
	return FIPS_mode();
}

static inline int
_goboringcrypto_FIPS_mode_set(int r)
{
	return FIPS_mode_set(r);
}


#include <openssl/rand.h>

static inline int
_goboringcrypto_RAND_bytes(uint8_t* arg0, size_t arg1)
{
	return RAND_bytes(arg0, arg1);
}


#include <openssl/obj_mac.h>

enum {
	GO_NID_md5_sha1 = NID_md5_sha1,

	GO_NID_secp224r1 = NID_secp224r1,
	GO_NID_X9_62_prime256v1 = NID_X9_62_prime256v1,
	GO_NID_secp384r1 = NID_secp384r1,
	GO_NID_secp521r1 = NID_secp521r1,

	GO_NID_sha224 = NID_sha224,
	GO_NID_sha256 = NID_sha256,
	GO_NID_sha384 = NID_sha384,
	GO_NID_sha512 = NID_sha512,
};

#include <openssl/sha.h>

typedef SHA_CTX GO_SHA_CTX;
static inline int
_goboringcrypto_SHA1_Init(GO_SHA_CTX* arg0)
{
	return SHA1_Init(arg0);
}

static inline int
_goboringcrypto_SHA1_Update(GO_SHA_CTX* arg0, const void* arg1, size_t arg2)
{
	return SHA1_Update(arg0, arg1, arg2);
}

static inline int
_goboringcrypto_SHA1_Final(uint8_t* arg0, GO_SHA_CTX* arg1)
{
	return SHA1_Final(arg0, arg1);
}


typedef SHA256_CTX GO_SHA256_CTX;
static inline int
_goboringcrypto_SHA224_Init(GO_SHA256_CTX* arg0)
{
	return SHA224_Init(arg0);
}

static inline int
_goboringcrypto_SHA224_Update(GO_SHA256_CTX* arg0, const void* arg1, size_t arg2)
{
	return SHA224_Update(arg0, arg1, arg2);
}

static inline int
_goboringcrypto_SHA224_Final(uint8_t* arg0, GO_SHA256_CTX* arg1)
{
	return SHA224_Final(arg0, arg1);
}

static inline int
_goboringcrypto_SHA256_Init(GO_SHA256_CTX* arg0)
{
	return SHA256_Init(arg0);
}

static inline int
_goboringcrypto_SHA256_Update(GO_SHA256_CTX* arg0, const void* arg1, size_t arg2)
{
	return SHA256_Update(arg0, arg1, arg2);
}

static inline int
_goboringcrypto_SHA256_Final(uint8_t* arg0, GO_SHA256_CTX* arg1)
{
	return SHA256_Final(arg0, arg1);
}


typedef SHA512_CTX GO_SHA512_CTX;
static inline int
_goboringcrypto_SHA384_Init(GO_SHA512_CTX* arg0)
{
	return SHA384_Init(arg0);
}

static inline int
_goboringcrypto_SHA384_Update(GO_SHA512_CTX* arg0, const void* arg1, size_t arg2)
{
	return SHA384_Update(arg0, arg1, arg2);
}

static inline int
_goboringcrypto_SHA384_Final(uint8_t* arg0, GO_SHA512_CTX* arg1)
{
	return SHA384_Final(arg0, arg1);
}

static inline int
_goboringcrypto_SHA512_Init(GO_SHA512_CTX* arg0)
{
	return SHA512_Init(arg0);
}

static inline int
_goboringcrypto_SHA512_Update(GO_SHA512_CTX* arg0, const void* arg1, size_t arg2)
{
	return SHA512_Update(arg0, arg1, arg2);
}

static inline int
_goboringcrypto_SHA512_Final(uint8_t* arg0, GO_SHA512_CTX* arg1)
{
	return SHA512_Final(arg0, arg1);
}


#include <openssl/evp.h>

typedef EVP_MD GO_EVP_MD;
static inline const GO_EVP_MD*
_goboringcrypto_EVP_md4(void)
{
	return EVP_md4();
}

static inline const GO_EVP_MD*
_goboringcrypto_EVP_md5(void)
{
	return EVP_md5();
}

const GO_EVP_MD* _goboringcrypto_EVP_md5_sha1(void);
static inline const GO_EVP_MD*
_goboringcrypto_EVP_sha1(void)
{
	return EVP_sha1();
}

static inline const GO_EVP_MD*
_goboringcrypto_EVP_sha224(void)
{
	return EVP_sha224();
}

static inline const GO_EVP_MD*
_goboringcrypto_EVP_sha256(void)
{
	return EVP_sha256();
}

static inline const GO_EVP_MD*
_goboringcrypto_EVP_sha384(void)
{
	return EVP_sha384();
}

static inline const GO_EVP_MD*
_goboringcrypto_EVP_sha512(void)
{
	return EVP_sha512();
}

static inline int
_goboringcrypto_EVP_MD_type(const GO_EVP_MD* arg0)
{
	return EVP_MD_type(arg0);
}

static inline size_t
_goboringcrypto_EVP_MD_size(const GO_EVP_MD* arg0)
{
	return EVP_MD_size(arg0);
}


#include <openssl/hmac.h>

typedef HMAC_CTX GO_HMAC_CTX;
static inline void
_goboringcrypto_HMAC_CTX_init(GO_HMAC_CTX* arg0)
{
	HMAC_CTX_init(arg0);
}

static inline void
_goboringcrypto_HMAC_CTX_cleanup(GO_HMAC_CTX* arg0)
{
	HMAC_CTX_cleanup(arg0);
}

static inline int
_goboringcrypto_HMAC_Init(GO_HMAC_CTX* arg0, const void* arg1, int arg2, const GO_EVP_MD* arg3)
{
	return HMAC_Init(arg0, arg1, arg2, arg3);
}

static inline int
_goboringcrypto_HMAC_Update(GO_HMAC_CTX* arg0, const uint8_t* arg1, size_t arg2)
{
	return HMAC_Update(arg0, arg1, arg2);
}

static inline int
_goboringcrypto_HMAC_Final(GO_HMAC_CTX* arg0, uint8_t* arg1, unsigned int* arg2)
{
	return HMAC_Final(arg0, arg1, arg2);
}

static inline size_t
_goboringcrypto_HMAC_size(const GO_HMAC_CTX* arg0)
{
	return HMAC_size(arg0);
}

int _goboringcrypto_HMAC_CTX_copy_ex(GO_HMAC_CTX *dest, const GO_HMAC_CTX *src);

#include <openssl/aes.h>


void
_goboringcrypto_EVP_AES_ctr128_enc(EVP_CIPHER_CTX *ctx, const uint8_t* in, uint8_t* out, size_t len);

static inline int
_goboringcrypto_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc)
{
	return EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
}

static inline int
_goboringcrypto_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, const unsigned char *in, int inl)
{
	return EVP_CipherUpdate(ctx, out, outl, in, inl);
}

int
_goboringcrypto_EVP_AES_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);

enum {
	GO_AES_ENCRYPT = 1,
	GO_AES_DECRYPT = 0
};
void
_goboringcrypto_EVP_AES_cbc_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t* arg0, uint8_t* arg1, size_t arg2, const uint8_t *a, const int arg5);

void
EVP_AES_cbc_enc(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

void
EVP_AES_cbc_dec(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

typedef ENGINE GO_ENGINE;

#include <openssl/bn.h>

typedef BN_CTX GO_BN_CTX;
typedef BIGNUM GO_BIGNUM;
static inline GO_BIGNUM*
_goboringcrypto_BN_new(void)
{
	return BN_new();
}

static inline void
_goboringcrypto_BN_free(GO_BIGNUM* arg0)
{
	BN_free(arg0);
}

static inline unsigned
_goboringcrypto_BN_num_bits(const GO_BIGNUM* arg0)
{
	return BN_num_bits(arg0);
}

static inline unsigned
_goboringcrypto_BN_num_bytes(const GO_BIGNUM* arg0)
{
	return BN_num_bytes(arg0);
}

static inline int
_goboringcrypto_BN_is_negative(const GO_BIGNUM* arg0)
{
	return BN_is_negative(arg0);
}

static inline GO_BIGNUM*
_goboringcrypto_BN_bin2bn(const uint8_t* arg0, size_t arg1, GO_BIGNUM* arg2)
{
	return BN_bin2bn(arg0, arg1, arg2);
}

static inline size_t
_goboringcrypto_BN_bn2bin(const GO_BIGNUM* arg0, uint8_t* arg1)
{
	return BN_bn2bin(arg0, arg1);
}


#include <openssl/ec.h>

typedef EC_GROUP GO_EC_GROUP;
static inline GO_EC_GROUP*
_goboringcrypto_EC_GROUP_new_by_curve_name(int arg0)
{
	return EC_GROUP_new_by_curve_name(arg0);
}

static inline void
_goboringcrypto_EC_GROUP_free(GO_EC_GROUP* arg0)
{
	EC_GROUP_free(arg0);
}


typedef EC_POINT GO_EC_POINT;
static inline GO_EC_POINT*
_goboringcrypto_EC_POINT_new(const GO_EC_GROUP* arg0)
{
	return EC_POINT_new(arg0);
}

static inline void
_goboringcrypto_EC_POINT_free(GO_EC_POINT* arg0)
{
	EC_POINT_free(arg0);
}

static inline int
_goboringcrypto_EC_POINT_get_affine_coordinates_GFp(const GO_EC_GROUP* arg0, const GO_EC_POINT* arg1, GO_BIGNUM* arg2, GO_BIGNUM* arg3, GO_BN_CTX* arg4)
{
	return EC_POINT_get_affine_coordinates_GFp(arg0, arg1, arg2, arg3, arg4);
}

static inline int
_goboringcrypto_EC_POINT_set_affine_coordinates_GFp(const GO_EC_GROUP* arg0, GO_EC_POINT* arg1, const GO_BIGNUM* arg2, const GO_BIGNUM* arg3, GO_BN_CTX* arg4)
{
	return EC_POINT_set_affine_coordinates_GFp(arg0, arg1, arg2, arg3, arg4);
}


typedef EC_KEY GO_EC_KEY;
static inline GO_EC_KEY*
_goboringcrypto_EC_KEY_new(void)
{
	return EC_KEY_new();
}

static inline GO_EC_KEY*
_goboringcrypto_EC_KEY_new_by_curve_name(int arg0)
{
	return EC_KEY_new_by_curve_name(arg0);
}

static inline void
_goboringcrypto_EC_KEY_free(GO_EC_KEY* arg0)
{
	EC_KEY_free(arg0);
}

static inline const GO_EC_GROUP*
_goboringcrypto_EC_KEY_get0_group(const GO_EC_KEY* arg0)
{
	return EC_KEY_get0_group(arg0);
}

static inline int
_goboringcrypto_EC_KEY_generate_key_fips(GO_EC_KEY* arg0)
{
	return EC_KEY_generate_key(arg0);
}

static inline int
_goboringcrypto_EC_KEY_set_private_key(GO_EC_KEY* arg0, const GO_BIGNUM* arg1)
{
	return EC_KEY_set_private_key(arg0, arg1);
}

static inline int
_goboringcrypto_EC_KEY_set_public_key(GO_EC_KEY* arg0, const GO_EC_POINT* arg1)
{
	return EC_KEY_set_public_key(arg0, arg1);
}

static inline const GO_BIGNUM*
_goboringcrypto_EC_KEY_get0_private_key(const GO_EC_KEY* arg0)
{
	return EC_KEY_get0_private_key(arg0);
}

static inline const GO_EC_POINT*
_goboringcrypto_EC_KEY_get0_public_key(const GO_EC_KEY* arg0)
{
	return EC_KEY_get0_public_key(arg0);
}

// TODO: EC_KEY_check_fips?

#include <openssl/ecdsa.h>

typedef ECDSA_SIG GO_ECDSA_SIG;
static inline GO_ECDSA_SIG*
_goboringcrypto_ECDSA_SIG_new(void)
{
	return ECDSA_SIG_new();
}

static inline void
_goboringcrypto_ECDSA_SIG_free(GO_ECDSA_SIG* arg0)
{
	ECDSA_SIG_free(arg0);
}

static inline GO_ECDSA_SIG*
_goboringcrypto_ECDSA_do_sign(const uint8_t* arg0, size_t arg1, const GO_EC_KEY* arg2)
{
	return ECDSA_do_sign(arg0, arg1, (GO_EC_KEY*) arg2);
}

static inline int
_goboringcrypto_ECDSA_do_verify(const uint8_t* arg0, size_t arg1, const GO_ECDSA_SIG* arg2, const GO_EC_KEY* arg3)
{
	return ECDSA_do_verify(arg0, arg1, arg2, (GO_EC_KEY*) arg3);
}

static inline int
_goboringcrypto_ECDSA_sign(int arg0, const uint8_t* arg1, size_t arg2, uint8_t* arg3, unsigned int* arg4, const GO_EC_KEY* arg5)
{
	return ECDSA_sign(arg0, arg1, arg2, arg3, arg4, (GO_EC_KEY*) arg5);
}

static inline size_t
_goboringcrypto_ECDSA_size(const GO_EC_KEY* arg0)
{
	return ECDSA_size(arg0);
}

static inline int
_goboringcrypto_ECDSA_verify(int arg0, const uint8_t* arg1, size_t arg2, const uint8_t* arg3, size_t arg4, const GO_EC_KEY* arg5)
{
	return ECDSA_verify(arg0, arg1, arg2, arg3, arg4, (GO_EC_KEY*) arg5);
}


#include <openssl/rsa.h>

// Note: order of struct fields here is unchecked.
typedef RSA GO_RSA;
typedef BN_GENCB GO_BN_GENCB;
static inline GO_RSA*
_goboringcrypto_RSA_new(void)
{
	return RSA_new();
}

static inline void
_goboringcrypto_RSA_free(GO_RSA* arg0)
{
	RSA_free(arg0);
}

static inline int
_goboringcrypto_RSA_sign(int arg0, const uint8_t* arg1, unsigned int arg2, uint8_t *arg3, unsigned int *arg4, GO_RSA* arg5)
{
	return RSA_sign(arg0, arg1, arg2, arg3, arg4, arg5);
}

static inline int
_goboringcrypto_RSA_verify(int arg0, const uint8_t *arg1, size_t arg2, const uint8_t *arg3, size_t arg4, GO_RSA* arg5)
{
	return RSA_verify(arg0, arg1, arg2, arg3, arg4, arg5);
}

void _goboringcrypto_RSA_get0_key(const GO_RSA*, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d);
void _goboringcrypto_RSA_get0_factors(const GO_RSA*, const GO_BIGNUM **p, const GO_BIGNUM **q);
void _goboringcrypto_RSA_get0_crt_params(const GO_RSA*, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmp2, const GO_BIGNUM **iqmp);
static inline int
_goboringcrypto_RSA_generate_key_ex(GO_RSA* arg0, int arg1, GO_BIGNUM* arg2, GO_BN_GENCB* arg3)
{
	return RSA_generate_key_ex(arg0, arg1, arg2, arg3);
}

int _goboringcrypto_RSA_generate_key_fips(GO_RSA*, int, GO_BN_GENCB*);
enum {
	GO_RSA_PKCS1_PADDING = 1,
	GO_RSA_NO_PADDING = 3,
	GO_RSA_PKCS1_OAEP_PADDING = 4,
	GO_RSA_PKCS1_PSS_PADDING = 6,
};

int _goboringcrypto_RSA_sign_pss_mgf1(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, const GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len);
int _goboringcrypto_RSA_sign_raw(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);

int _goboringcrypto_RSA_verify_pss_mgf1(GO_RSA*, const uint8_t *msg, size_t msg_len, const GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len, const uint8_t *sig, size_t sig_len);
int _goboringcrypto_RSA_verify_raw(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);

static inline unsigned
_goboringcrypto_RSA_size(const GO_RSA* arg0)
{
	return RSA_size(arg0);
}

static inline int
_goboringcrypto_RSA_check_key(const GO_RSA* arg0)
{
	return RSA_check_key(arg0);
}


#include <openssl/evp.h>

int _goboringcrypto_EVP_CIPHER_CTX_seal(
		uint8_t *out, uint8_t *nonce,
		uint8_t *aad, size_t aad_len,
		uint8_t *plaintext, size_t plaintext_len,
		size_t *ciphertext_len, uint8_t *key, int key_size);

int _goboringcrypto_EVP_CIPHER_CTX_open(
		uint8_t *ciphertext, int ciphertext_len,
		uint8_t *aad, int aad_len,
		uint8_t *tag, uint8_t *key, int key_size,
		uint8_t *nonce, int nonce_len,
		uint8_t *plaintext, size_t *plaintext_len);

typedef EVP_PKEY GO_EVP_PKEY;
static inline GO_EVP_PKEY*
_goboringcrypto_EVP_PKEY_new(void)
{
	return EVP_PKEY_new();
}

static inline void
_goboringcrypto_EVP_PKEY_free(GO_EVP_PKEY* arg0)
{
	EVP_PKEY_free(arg0);
}

static inline int
_goboringcrypto_EVP_PKEY_set1_RSA(GO_EVP_PKEY* arg0, GO_RSA* arg1)
{
	return EVP_PKEY_set1_RSA(arg0, arg1);
}


typedef EVP_PKEY_CTX GO_EVP_PKEY_CTX;

static inline GO_EVP_PKEY_CTX*
_goboringcrypto_EVP_PKEY_CTX_new(GO_EVP_PKEY* arg0, GO_ENGINE* arg1)
{
	return EVP_PKEY_CTX_new(arg0, arg1);
}

static inline void
_goboringcrypto_EVP_PKEY_CTX_free(GO_EVP_PKEY_CTX* arg0)
{
	EVP_PKEY_CTX_free(arg0);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(GO_EVP_PKEY_CTX* ctx, uint8_t* l, size_t llen)
{

        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)l);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(GO_EVP_PKEY_CTX* ctx, const GO_EVP_MD* md)
{
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)md);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(GO_EVP_PKEY_CTX* arg0, int padding)
{
	return EVP_PKEY_CTX_set_rsa_padding(arg0, padding);
}

static inline int
_goboringcrypto_EVP_PKEY_decrypt(GO_EVP_PKEY_CTX* arg0, uint8_t* arg1, size_t* arg2, const uint8_t* arg3, size_t arg4)
{
	return EVP_PKEY_decrypt(arg0, arg1, arg2, arg3, arg4);
}

static inline int
_goboringcrypto_EVP_PKEY_encrypt(GO_EVP_PKEY_CTX* arg0, uint8_t* arg1, size_t* arg2, const uint8_t* arg3, size_t arg4)
{
	return EVP_PKEY_encrypt(arg0, arg1, arg2, arg3, arg4);
}

static inline int
_goboringcrypto_EVP_PKEY_decrypt_init(GO_EVP_PKEY_CTX* arg0)
{
	return EVP_PKEY_decrypt_init(arg0);
}

static inline int
_goboringcrypto_EVP_PKEY_encrypt_init(GO_EVP_PKEY_CTX* arg0)
{
	return EVP_PKEY_encrypt_init(arg0);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(GO_EVP_PKEY_CTX* arg0, const GO_EVP_MD* arg1)
{
	return EVP_PKEY_CTX_set_rsa_mgf1_md(arg0, arg1);
}

static inline int
_goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(GO_EVP_PKEY_CTX* arg0, int arg1)
{
	return EVP_PKEY_CTX_set_rsa_pss_saltlen(arg0, arg1);
}

static inline int
_goboringcrypto_EVP_PKEY_sign_init(GO_EVP_PKEY_CTX* arg0)
{
	return EVP_PKEY_sign_init(arg0);
}

static inline int
_goboringcrypto_EVP_PKEY_verify_init(GO_EVP_PKEY_CTX* arg0)
{
	return EVP_PKEY_verify_init(arg0);
}

static inline int
_goboringcrypto_EVP_PKEY_sign(GO_EVP_PKEY_CTX* arg0, uint8_t* arg1, size_t* arg2, const uint8_t* arg3, size_t arg4)
{
	return EVP_PKEY_sign(arg0, arg1, arg2, arg3, arg4);
}

