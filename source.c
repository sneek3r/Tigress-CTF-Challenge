#include "/usr/local/bin/tigresspkg/4.0.7/tigress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void print_hash_as_bytes(unsigned char *hash, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("0x%02x", hash[i]);
        if (i != length - 1)
            printf(", ");
    }
    printf("\n");
}

unsigned char* compute_sha256(const char *input, unsigned int *hash_len) {
    unsigned char *hash = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    if (!hash) {
        fprintf(stderr, "Error allocating memory for hash!\n");
        return NULL;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL) {
        fprintf(stderr, "Error creating EVP context!\n");
        free(hash);
        return NULL;
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error initializing SHA-256!\n");
        EVP_MD_CTX_free(context);
        free(hash);
        return NULL;
    }

    if (EVP_DigestUpdate(context, input, strlen(input)) != 1) {
        fprintf(stderr, "Error updating SHA-256!\n");
        EVP_MD_CTX_free(context);
        free(hash);
        return NULL;
    }

    if (EVP_DigestFinal_ex(context, hash, hash_len) != 1) {
        fprintf(stderr, "Error finalizing SHA-256!\n");
        EVP_MD_CTX_free(context);
        free(hash);
        return NULL;
    }

    EVP_MD_CTX_free(context);
    return hash;
}

unsigned char* get_stored_hash() {
    static unsigned char stored_hash[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    return stored_hash;
}

unsigned char* get_encrypted_message() {
    static unsigned char encrypted_message[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    return encrypted_message;
}

int is_key_matching(const char *input_username) {
    unsigned int hash_len;
    unsigned char *input_hash = compute_sha256(input_username, &hash_len);
    unsigned char *stored_hash = get_stored_hash();

    if (input_hash == NULL) return 0;

    int result = (memcmp(input_hash, stored_hash, hash_len) == 0);
    free(input_hash);
    return result;
}

char* decrypt_message(const unsigned char *encrypted_message, size_t message_len, const unsigned char *key, size_t key_length) {
    char *decrypted_message = (char*)malloc(message_len + 1);
    if (!decrypted_message) {
        fprintf(stderr, "Error allocating memory for decrypted message!\n");
        return NULL;
    }

    for (size_t i = 0; i < message_len; ++i) {
        unsigned char byte = encrypted_message[i];
        unsigned char current_key = key[i % key_length];

        byte ^= 0xA5;
        byte = (byte >> 3) | (byte << (8 - 3));
        byte ^= current_key;

        decrypted_message[i] = byte;
    }
    decrypted_message[message_len] = '\0';
    return decrypted_message;
}

int main() {
    char username[256];
    printf("Enter your username: ");
    if (fgets(username, sizeof(username), stdin) == NULL) {
        fprintf(stderr, "Error reading username!\n");
        return 1;
    }
    username[strcspn(username, "\n")] = '\0';

    if (is_key_matching(username)) {
        unsigned char *encrypted_message = get_encrypted_message();
        unsigned char *stored_hash = get_stored_hash();

        char *decrypted_message = decrypt_message(encrypted_message, 30, stored_hash, 32);
        if (decrypted_message) {
            printf("Decrypted Flag: %s\n", decrypted_message);
            free(decrypted_message);
        }
    } else {
        printf("Username does not match stored hash.\n");
    }

    return 0;
}
