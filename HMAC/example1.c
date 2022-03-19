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

    if(argc != 2){
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

    unsigned char key[] = "1234567887654321"; // ASCII CHARACTERS

    HMAC_CTX *hmac_ctx = HMAC_CTX_new();

    if(!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha1(), NULL))
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!HMAC_Update(hmac_ctx, buffer, n_read))
           handle_errors();
    }
    
    unsigned char hmac_value[HMAC_size(hmac_ctx)];
    int hmac_len;

    if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    
    HMAC_CTX_free(hmac_ctx);

    printf("The HMAC is: ");
    for(int i = 0; i < hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}