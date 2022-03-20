#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main(){

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char key[] = "123456789abcdef"; // ASCII 
    unsigned char iv[] = "abcdef123456789"; // ASCII 

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);

    unsigned char plaintext[] =  "This variable contains the data to encrypt"; // 44 bytes
    unsigned char ciphertext[48];
    int lenght;
    int ciphertext_len = 0;
    
    EVP_CipherUpdate(ctx, ciphertext, &lenght, plaintext, strlen(plaintext));

    printf("After update: %d\n", lenght);
    ciphertext_len += lenght;

    EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &lenght);

    printf("After final: %d\n", lenght);
    ciphertext_len += lenght;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of ciphertext = %d\n", ciphertext_len);

    for(int i = 0; i < ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}