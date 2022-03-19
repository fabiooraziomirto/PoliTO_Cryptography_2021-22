#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

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
    
    EVP_MD_CTX *md, *md2;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    md = EVP_MD_CTX_new();
    md2 = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();

    if(!EVP_DigestInit(md2, EVP_sha512()))
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;

    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
        if(!EVP_DigestUpdate(md2, buffer, n_read))
            handle_errors();
    }


//    EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;

    unsigned char md2_value[EVP_MD_size(EVP_sha512())];
    int md2_len;

    if(!EVP_DigestFinal(md, md_value, &md_len))
        handle_errors();
    
    if(!EVP_DigestFinal(md2, md2_value, &md2_len))
        handle_errors();

    EVP_MD_CTX_free(md);
    EVP_MD_CTX_free(md2);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    //printf("The digest is: ");
    /*for(int i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
    }*/

    unsigned char sha512_low[256], sha512_high[256];
    int j = 0;

    for(int i = 0; i < md2_len; i++){
        if(i < 32)
            sha512_high[i] = md2_value[i];
        else
            sha512_low[j++] = md2_value[i];        
    }
    
    printf("Entire 512 digest\n");
    for(int i = 0; i < md2_len; i++){
        printf("%02x", md2_value[i]);
    }
    printf("\n");
    
    printf("256 low bit digest\n");
    for(int i = 0; i < md2_len/2; i++){
        printf("%02x", sha512_low[i]);
    }
    printf("\n");
    printf("256 high bit digest\n");
    for(int i = 0; i < md2_len/2; i++){
        printf("%02x", sha512_high[i]);
    }
    printf("\n");
    
    unsigned char result[md2_len], resultAnd[md2_len];

    for(int i = 0; i < md2_len; i++){
        resultAnd[i] = sha512_low[i]&sha512_high[i];
    }

    
    for(int i = 0; i < md_len; i++){
         result[i] = md_value[i]^resultAnd[i];
    }
    
    printf("Result:\n");
    for(int i = 0; i < md_len; i++){
        printf("%02x", result[i]);
    }

    return 0;
}