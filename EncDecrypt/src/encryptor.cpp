#include <openssl/evp.h>
#include <openssl/aes.h>
#include <vector>
#include <stdexcept>
#include <cstring> // For std::memset

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set padding.");
    }
    std::vector<unsigned char> encrypted_data;
    encrypted_data.resize(data.size() + AES_BLOCK_SIZE); // Ensure enough space for padding

    int len;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, data.data(), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    encrypted_data.resize(ciphertext_len); // Resize to actual length

    EVP_CIPHER_CTX_free(ctx);

    return encrypted_data;
}

std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& encrypted_data, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    // Enable padding
    if (EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set padding");
    }

    std::vector<unsigned char> decrypted_data(encrypted_data.size() + AES_BLOCK_SIZE); // Reserve enough space for decrypted data

    int len;
    int plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_data.data(), encrypted_data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    plaintext_len += len;

    decrypted_data.resize(plaintext_len); // Resize to actual length

    EVP_CIPHER_CTX_free(ctx);

    return decrypted_data;
}

