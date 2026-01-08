#ifndef AES_ENCRYPT_H
#define AES_ENCRYPT_H
#include <stdint.h>

// Initialize AES (expand key schedule). Call once at startup.
void aes_init();

// Encrypt plaintext buffer of given length.
// Outputs IV+ciphertext into out_cipher.
// Returns (plaintext_len + 16) = ciphertext length.
int aes_encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *out_cipher);

// Decrypt ciphertext buffer of given length.
// Expects the first 16 bytes to be the IV.
// Outputs plaintext into out_plain, returns plaintext length (cipher_len - 16).
int aes_decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *out_plain);

#endif

