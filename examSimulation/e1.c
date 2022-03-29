#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>


#define MAX 32
#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(){

    ERR_load_crypto_strings();
        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();
    unsigned char r1[MAX], r2[MAX];

    if(RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    if(!RAND_bytes(r1, MAX))
        handle_errors();
    if(!RAND_bytes(r2,MAX))
        handle_errors();
        
    EVP_MD_CTX *md = EVP_MD_CTX_new();

       
    EVP_DigestInit(md, EVP_sha256());

        
    EVP_DigestUpdate(md, r1, strlen(r1));
    EVP_DigestUpdate(md, "key", strlen("key"));
    EVP_DigestUpdate(md, r2, strlen(r2));

    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;

       
    EVP_DigestFinal_ex(md, md_value, &md_len);

        
	EVP_MD_CTX_free(md);

        printf("The digest is: ");
        for(int i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("\n");

     RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 4096;
    unsigned long e = RSA_F4;

    // 1. generate the RSA key
    bne = BN_new();
    if(!BN_set_word(bne,e))
        handle_errors();

    /*
    int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    */
    rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, 4096, bne, NULL)) /* callback not needed for our purposes */
        handle_errors();


    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];

    if((encrypted_data_len = RSA_public_encrypt(md_len, md_value, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            handle_errors();

    printf("%s\n", encrypted_data);

    RSA_free(rsa_keypair);
    BN_free(bne);

    return 0;

}