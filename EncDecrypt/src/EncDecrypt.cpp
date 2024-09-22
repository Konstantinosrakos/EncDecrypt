#include <iostream>
#include <vector>
#include <fstream>
#include <iterator>
#include <string>
#include <stdexcept>
#include <filesystem>
#include "file_handler.h"
#include "encryptor.h"
#include "assert.h"
#include "Password.h"

const std::string FILEPATH = "..\\test\\test.jpg";
const std::string FILEPATH_W = "..\\test\\testimage_encrypted.jpg";

int main() {


    unsigned char key[32] = { "1234567890123456789012345678901" };
    unsigned char iv[16] = { "123456789012345" };
    const std::string pass = "secret";
    std::vector<unsigned char> data;
    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> decrypted_data;

    Password myPassword(pass);

    try {
        data = readFile(FILEPATH);
    }
    catch (const std::exception e)
    {
        std::cerr << "File read error: " << e.what() << std::endl;
        return 1;
    }

    try {
        encrypted_data = aes_encrypt(data, key, iv);
    }
    catch (const std::exception& e) {
        std::cerr << "Encryption failed: " << e.what() << std::endl;
        return 1;
    }

    try {
        decrypted_data = aes_decrypt(encrypted_data, key, iv);
    }
    catch (const std::exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        return 1;
    }

    std::memset(key, 0x00, sizeof(key));
    std::memset(iv, 0x00, sizeof(iv));

    try {
        writeFile(FILEPATH_W, decrypted_data);
    }
    catch (const std::exception& e) {
        std::cerr << "File write error: " << e.what() << std::endl;
        return 1;
    }

    if (decrypted_data == data) {
        std::cout << "Decryption successful" << std::endl;
    }
    else {
        std::cerr << "Decrypted data does not match the original" << std::endl;
        return 5;
    }
}
