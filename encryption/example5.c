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
// argv[2] --> key (hexstring)
// argv[3] --> IV (hexstring)
// argv[4] --> file output
// save in a buffer in memory the result

int main(int argc, char **argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(argc != 5){
        fprintf(stderr, "Invalid parameters. Usage %s input_file key IV output_file\n", argv[0]);
        exit(1);
    }

    FILE *f_in, *f_out;
    if((f_in = fopen(argv[1], "r")) == NULL || (f_out = fopen(argv[4], "wb")) == NULL){
        fprintf(stderr, "Errors opening the input file: %s\n", argv[1]);
        exit(-1);
    }

    if((strlen(argv[2])/2) != 32){
        fprintf(stderr, "Wrong key lenght.\n");
        exit(-1);
    }

    unsigned char key[strlen(argv[2])/2];
    // convert hexstring in binary
    for(int i = 0; i < strlen(argv[2])/2; i++){
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);
    }

    if((strlen(argv[3])/2) != 32){
        fprintf(stderr, "Wrong IV lenght.\n");
        exit(-1);
    }

    unsigned char IV[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2; i++){
        sscanf(&argv[3][2*i], "%2hhx", &IV[i]);
    }

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, ENCRYPT))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXSIZE];

    unsigned char ciphertext[MAXSIZE + 16];

    int lenght, ciphertext_len = 0;

    while((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0){
        if(!EVP_CipherUpdate(ctx, ciphertext, &lenght, buffer, n_read))
            handle_errors();

        ciphertext_len += lenght;

        if(fwrite(ciphertext, 1, lenght, f_out) < lenght){
            fprintf(stderr, "Error in writing into the output fiile\n");
            abort();
        }

    }


     if(!EVP_CipherFinal(ctx, ciphertext, &lenght))
            handle_errors();
    ciphertext_len += lenght;

    if(fwrite(ciphertext, 1, lenght, f_out) < lenght){
        fprintf(stderr, "Error in writing into the output fiile\n");
        abort();
    }


    EVP_CIPHER_CTX_free(ctx);

    printf("Size of ciphertext = %d\n", ciphertext_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);
    fclose(f_out);

    return 0;
}