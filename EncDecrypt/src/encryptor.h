#pragma once
#include <string>
#include <vector>

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv);
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& encrypted_data, const unsigned char* key, const unsigned char* iv);