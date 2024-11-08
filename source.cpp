#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <iomanip>

void print_hash_as_bytes(const std::vector<unsigned char>& hash) {
    for (size_t i = 0; i < hash.size(); ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        if (i != hash.size() - 1)
            std::cout << ", ";
    }
    std::cout << std::endl;
}

std::vector<unsigned char> compute_sha256(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        std::cerr << "Error creating EVP context!" << std::endl;
        return {};
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Error initializing SHA-256!" << std::endl;
        EVP_MD_CTX_free(context);
        return {};
    }

    if (EVP_DigestUpdate(context, input.c_str(), input.size()) != 1) {
        std::cerr << "Error updating SHA-256!" << std::endl;
        EVP_MD_CTX_free(context);
        return {};
    }

    if (EVP_DigestFinal_ex(context, hash, &hash_len) != 1) {
        std::cerr << "Error finalizing SHA-256!" << std::endl;
        EVP_MD_CTX_free(context);
        return {};
    }

    EVP_MD_CTX_free(context);
    return std::vector<unsigned char>(hash, hash + hash_len);
}

std::vector<unsigned char> stored_hash = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

std::vector<unsigned char> encrypted_message = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool is_key_matching(const std::string& input_username) {
    std::vector<unsigned char> input_hash = compute_sha256(input_username);
    return input_hash == stored_hash;
}

std::string decrypt_message(const std::vector<unsigned char>& encrypted_message, const std::vector<unsigned char>& key) {
    std::string decrypted_message = std::string(encrypted_message.begin(), encrypted_message.end());
    size_t key_length = key.size();

    for (size_t i = 0; i < encrypted_message.size(); ++i) {
        unsigned char byte = decrypted_message[i];
        unsigned char current_key = key[i % key_length];

        byte ^= 0xA5;
        byte = (byte >> 3) | (byte << (8 - 3));
        byte ^= current_key;

        decrypted_message[i] = byte;
    }

    return decrypted_message;
}

int main() {
    std::string username;

    std::cout << "Enter your username: ";
    std::getline(std::cin, username);

    if (is_key_matching(username)) {
        std::string decrypted_message = decrypt_message(encrypted_message, stored_hash);
        std::cout << "Decrypted Flag: " << decrypted_message << std::endl;
    }

    return 0;
}
