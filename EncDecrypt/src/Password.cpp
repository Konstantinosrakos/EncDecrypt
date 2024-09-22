#include "Password.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdexcept>

//rate this class and give imporvements
//https://www.codeproject.com/Articles/1279322/Encrypting-Decrypting-Files-Using-OpenSSL-Library

Password::Password(const std::string& password) : password_(password)
{
	generateSalt();
    generateInfo();
	deriveKey();
}
Password::Password( const std::string& password,
                    const std::vector<unsigned char>& salt,
                    const std::vector<unsigned char>& iv)
    : password_(password), salt_(salt), iv_(iv)
{
    generateInfo();
    deriveKey();
}


const std::vector<unsigned char>& Password::getSalt() const
{
	return salt_;
}


const std::vector<unsigned char>& Password::getKey() const
{
	return key_;
}

void Password::generateSalt()
{
	salt_.resize(salt_length_);

	if (RAND_bytes(salt_.data(), salt_length_) != 1) {
		throw std::runtime_error("Error generating random salt");
	}
}
void Password::generateInfo()
{
    info_ = "label";
}
void Password::generateDigest(const std::string& algorithm)
{
    digestAlgorithm_ = algorithm;
}

void Password::deriveKey()
{
    EVP_KDF* kdf;
    EVP_KDF_CTX* kctx = NULL;
    unsigned char derived[32];
    OSSL_PARAM params[5], * p = params;

    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        throw std::runtime_error("EVP_KDF_fetch");
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL) {
        throw std::runtime_error("EVP_KDF_CTX_new");
    }
    
    char keys[] = "sha256";
    /* Build up the parameters for the derivation */
    params[0] = OSSL_PARAM_construct_utf8_string("digest", keys, sizeof(keys) - 1);
    params[1] = OSSL_PARAM_construct_octet_string("salt", salt_.data(), (size_t)sizeof(salt_.data()));
    params[2] = OSSL_PARAM_construct_octet_string("key", password_.data(), (size_t)sizeof(password_.data()));
    params[3] = OSSL_PARAM_construct_octet_string("info", info_.data(), (size_t)sizeof(info_.data()));
    params[4] = OSSL_PARAM_construct_end();
    
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        throw std::runtime_error("EVP_KDF_CTX_set_params");
    }

    /* Do the derivation */
    if (EVP_KDF_derive(kctx, derived, sizeof(derived), NULL) <= 0) {
        throw std::runtime_error("EVP_KDF_derive");
    }

    /* Use the 32 bytes as a Key and IV */
    const unsigned char* key = derived + 0;
    const unsigned char* iv = derived + 16;

    printf("Key: ");
    for (size_t i = 0; i < 16; ++i)
        printf("%02x ", key[i]);
    printf("\n");

    printf("IV:  ");
    for (size_t i = 0; i < 16; ++i)
        printf("%02x ", iv[i]);
    printf("\n");

    EVP_KDF_CTX_free(kctx);


}
void Password::deriveKey(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& iv)
{
    return;
}