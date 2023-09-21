#include "library.h"
#include <iostream>

int main() {
    hello();
    std::string key = "0123456789abcdef";
    std::string plaintext = "Hello, World!";
    std::string ciphertext = encrypt(plaintext, key);
    std::string decrypted = decrypt(ciphertext, key);
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext: " << ciphertext << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
}