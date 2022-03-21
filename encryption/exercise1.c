#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0
#define MAXSIZE 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

// argv[1] --> input file
// argv[2] --> user algorithm


int main(int argc, char **argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(argc != 3){
        fprintf(stderr, "Invalid parameters. Usage %s input_file key IV\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Errors opening the input file: %s\n", argv[1]);
        exit(-1);
    }

   
    unsigned char key[] = "123456789abcdef"; // ASCII 
    unsigned char IV[] = "abcdef123456789"; // ASCII 

    const EVP_CIPHER *algo = EVP_get_cipherbyname(argv[2]);

    if(!EVP_CipherInit(ctx, algo, key, IV, ENCRYPT))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXSIZE];

    unsigned char ciphertext[100 * MAXSIZE];

    int lenght, ciphertext_len = 0;

    while((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0){
        if(ciphertext_len > (100 * MAXSIZE - n_read - EVP_CIPHER_CTX_block_size(ctx))){
            fprintf(stderr, "The file to cipher is larger than expected.\n");
            exit(-1);
        }

        if(!EVP_CipherUpdate(ctx, ciphertext+ciphertext_len, &lenght, buffer, n_read))
            handle_errors();
        ciphertext_len += lenght;
    }

     if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &lenght))
            handle_errors();
    ciphertext_len += lenght;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of ciphertext = %d\n", ciphertext_len);

    for(int i = 0; i < ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);
    
    return 0;
}