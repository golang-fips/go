// This file contains a port of the BoringSSL AEAD interface.

#include "goboringcrypto.h"
#include <openssl/err.h>

int _goboringcrypto_EVP_CIPHER_CTX_seal(
		uint8_t *out, uint8_t *nonce,
		uint8_t *aad, size_t aad_len,
		uint8_t *plaintext, size_t plaintext_len,
		size_t *ciphertext_len, uint8_t *key, int key_size) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int ret;

	if (plaintext_len == 0) {
		plaintext = "";
	}

	if (aad_len == 0) {
		aad = "";
	}

	// Create and initialise the context.
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		goto err;
	}

	switch(key_size) {
		case 128:
			if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
				goto err;
			}
			break;
		case 256:
			if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
				goto err;
			}
			break;
		default:
			goto err;
	}

	// Initialize nonce.
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) {
		goto err;
	}

	// Provide AAD data.
	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		goto err;
	}

	if (!EVP_EncryptUpdate(ctx, out, &len, plaintext, plaintext_len)) {
		goto err;
	}
	*ciphertext_len = len;

	if (!EVP_EncryptFinal_ex(ctx, out + len, &len)) {
		goto err;
	}
	*ciphertext_len += len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out+(*ciphertext_len))) {
		goto err;
	}
	*ciphertext_len += 16;
	ret = 1;

err:
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		return ret;
	} else {
		return 0;
	}
}

int _goboringcrypto_EVP_CIPHER_CTX_open(
		uint8_t *ciphertext, int ciphertext_len,
		uint8_t *aad, int aad_len,
		uint8_t *tag, uint8_t *key, int key_size,
		uint8_t *nonce, int nonce_len,
		uint8_t *plaintext, size_t *plaintext_len) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int ret;

	if (aad_len == 0) {
		aad = "";
	}

	// Create and initialise the context.
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

	switch(key_size) {
		case 128:
			if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
				goto err;
			}
			break;
		case 256:
			if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
				goto err;
			}
			break;
	}

	// Initialize key and nonce.
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
		goto err;
	}

	// Provide any AAD data.
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		goto err;
	}

	// Provide the message to be decrypted, and obtain the plaintext output.
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		goto err;
	}
	*plaintext_len = len;

	// Set expected tag value. Works in OpenSSL 1.0.1d and later.
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		goto err;
	}

	// Finalise the decryption. A positive return value indicates success,
	// anything else is a failure - the plaintext is not trustworthy.
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

err:
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		// Success
		*plaintext_len += len;
		return ret;
	} else {
		// Verify failed
		return 0;
	}
}
