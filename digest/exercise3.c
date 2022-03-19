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

    if(argc != 3){
        fprintf(stderr, "Invalid parameter num. Usage: %s string_to_hash\n", argv[0]);
        exit(-1);
    }
    
    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Couldn't open the input file, try again\n", argv[0]);
        exit(1);
    }

    const EVP_MD *md;
    EVP_MD_CTX *mda;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    md = EVP_get_digestbyname(argv[2]);

    mda = EVP_MD_CTX_new();
    if(!EVP_DigestInit_ex(mda, md, NULL))
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;

    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestUpdate(mda, buffer, n_read))
            handle_errors();
    }


//    EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    unsigned char md_value[EVP_MD_size(md)];
    int md_len;

    if(!EVP_DigestFinal_ex(mda, md_value, &md_len))
        handle_errors();

    EVP_MD_CTX_free(mda);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The digest is: ");
    for(int i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
    }
    printf("\n");


    return 0;
}