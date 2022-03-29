#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>


#define MAX 32
#define MAXBUF 1024

#define KEY_LENGTH  2048

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(){

    ERR_load_crypto_strings();
        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();

    unsigned char msg[] = "Text to encrypt";
    unsigned char key[] = "Text to encrypt";
        
    EVP_MD_CTX *md = EVP_MD_CTX_new();

       
    EVP_DigestInit(md, EVP_sha256());

        
    EVP_DigestUpdate(md, msg, strlen(msg));
    EVP_DigestUpdate(md, key, strlen(key));


    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;

       
    EVP_DigestFinal_ex(md, md_value, &md_len);

        
	EVP_MD_CTX_free(md);

    EVP_MD_CTX *md1 = EVP_MD_CTX_new();

       
    EVP_DigestInit(md1, EVP_sha256());

        
    EVP_DigestUpdate(md1, md_value, strlen(md_value));

    unsigned char md_value1[EVP_MD_size(EVP_sha256())];
    int md_len1;

       
    EVP_DigestFinal_ex(md1, md_value1, &md_len1);

    EVP_MD_CTX_free(md1);

        printf("Generating a fresh RSA (%d bits) keypair...\n", KEY_LENGTH);
        
    BIGNUM *bn_pub_exp = BN_new();
    BN_set_word(bn_pub_exp,RSA_F4);
    RSA  *keypair; //RSA data structure
    keypair = RSA_new();
    if(!RSA_generate_key_ex(keypair, KEY_LENGTH, bn_pub_exp, NULL))
        handle_errors();


    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(keypair)];


    if((encrypted_data_len = RSA_public_encrypt(strlen(md_value1)+1, md_value1, encrypted_data, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            return 1;

    return 0;


    return 0;
}