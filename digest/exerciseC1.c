#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(){
    char message[] = "Cryptography class 22-03-22";

    EVP_MD_CTX *md;

    md = EVP_MD_CTX_new();
    EVP_DigestInit(md, EVP_sha3_384());

    EVP_DigestUpdate(md, message, strlen(message));

    unsigned char md_value[EVP_MD_size(EVP_sha3_384())];
    int md_len;

    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

    printf("The digest is: ");
    for(int i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
    }
    printf("\n");


    return 0;
}