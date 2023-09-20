#include "library.h"

#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// Key and IV lengths for AES-256 encryption
const int AES_KEY_LENGTH = 32; // 256 bits
const int AES_BLOCK_SIZE = 16; // 128 bits

std::string encrypt(const std::string &plaintext, const std::string &key) {
    // Generate a random IV (Initialization Vector)
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        std::cerr << "Error generating IV." << std::endl;
        return "";
    }

    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), AES_KEY_LENGTH * 8, &aesKey) != 0) {
        std::cerr << "Error setting AES encryption key." << std::endl;
        return "";
    }

    // Padding plaintext to match the block size
    int plaintextLength = plaintext.length();
    int paddedLength = (plaintextLength / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    unsigned char paddedPlaintext[paddedLength];
    memset(paddedPlaintext, 0, paddedLength);
    memcpy(paddedPlaintext, plaintext.c_str(), plaintextLength);

    // Encrypt the data
    unsigned char ciphertext[paddedLength];
    AES_cbc_encrypt(paddedPlaintext, ciphertext, paddedLength, &aesKey, iv, AES_ENCRYPT);

    // Combine IV and ciphertext
    std::string result(reinterpret_cast<char *>(iv), AES_BLOCK_SIZE);
    result += std::string(reinterpret_cast<char *>(ciphertext), paddedLength);

    return result;
}

std::string decrypt(const std::string &ciphertext, const std::string &key) {
    if (ciphertext.length() < AES_BLOCK_SIZE) {
        std::cerr << "Invalid ciphertext." << std::endl;
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ciphertext.c_str(), AES_BLOCK_SIZE);

    AES_KEY aesKey;
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), AES_KEY_LENGTH * 8, &aesKey) != 0) {
        std::cerr << "Error setting AES decryption key." << std::endl;
        return "";
    }

    // Decrypt the data
    int ciphertextLength = ciphertext.length() - AES_BLOCK_SIZE;
    unsigned char plaintext[ciphertextLength];
    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(ciphertext.c_str() + AES_BLOCK_SIZE), plaintext, ciphertextLength, &aesKey, iv, AES_DECRYPT);

    // Remove padding
    int unpaddedLength = ciphertextLength;
    while (unpaddedLength > 0 && plaintext[unpaddedLength - 1] == 0) {
        unpaddedLength--;
    }

    return std::string(reinterpret_cast<char *>(plaintext), unpaddedLength);
}


void hello() {
    std::cout << "Hello, World!" << std::endl;
}
