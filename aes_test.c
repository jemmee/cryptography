// sudo dnf install openssl-devel gcc -y
//
// gcc -o aes_test aes_test.c -lssl -lcrypto
//
// ./aes_test

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int main() {
  // 1. Setup Key and Initialization Vector (IV)
  // For AES-256, the key must be 32 bytes and IV 16 bytes.
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
  unsigned char *iv = (unsigned char *)"0123456789012345";

  unsigned char *plaintext =
      (unsigned char *)"I am with you and will watch over you wherever you go, "
                       "and I will bring you back to this land.";
  unsigned char ciphertext[128];
  unsigned char decryptedtext[128];
  int len, ciphertext_len, decryptedtext_len;

  // 2. Encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    handle_errors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                             strlen((char *)plaintext)))
    handle_errors();
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handle_errors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  // 3. Decryption
  ctx = EVP_CIPHER_CTX_new();
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();

  if (1 !=
      EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
    handle_errors();
  decryptedtext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len))
    handle_errors();
  decryptedtext_len += len;

  decryptedtext[decryptedtext_len] = '\0'; // Null-terminate string
  EVP_CIPHER_CTX_free(ctx);

  // 4. Print Results
  printf("Plaintext: %s\n", plaintext);
  printf("Ciphertext (hex): ");
  for (int i = 0; i < ciphertext_len; i++)
    printf("%02x", ciphertext[i]);
  printf("\nDecrypted: %s\n", decryptedtext);

  return 0;
}