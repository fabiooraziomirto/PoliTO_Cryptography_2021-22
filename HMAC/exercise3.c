#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// first parameter is the name of the file to hash

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){

    if(argc != 3){
        fprintf(stderr, "Invalid parameter num. Usage: %s string_to_hash\n", argv[0]);
        exit(-1);
    }
    
    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Couldn't open the input file, try again\n", argv[0]);
        exit(1);
    }    

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char key[MAXBUF]; // ASCII CHARACTERS
    strcpy(key, argv[2]);
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));


    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key))
        handle_errors();

    unsigned char buffer[MAXBUF], buffer2[MAXBUF*2];
    int n_read;
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        for(int i = 0; i < n_read; i++){
            buffer2[i] = key[i]^buffer[i]^key[i];
        }
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer2, n_read))
           handle_errors();
    }
    
    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    size_t hmac_len;

    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    
    EVP_MD_CTX_free(hmac_ctx);

    printf("The HMAC is: ");
    for(int i = 0; i < hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");



    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}