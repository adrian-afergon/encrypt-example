#ifndef ENCRYPT_EXAMPLE_LIBRARY_H
#define ENCRYPT_EXAMPLE_LIBRARY_H
#include <string>

void hello();
std::string encrypt(const std::string &plaintext, const std::string &key);
std::string decrypt(const std::string &ciphertext, const std::string &key);


#endif //ENCRYPT_EXAMPLE_LIBRARY_H
