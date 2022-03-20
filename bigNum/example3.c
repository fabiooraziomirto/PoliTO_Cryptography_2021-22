#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();

    // openssl < 3.0 --> BN_generate_prime_ex();
    // openssl > 3.0 --> BN_generate_prime_ex2(); + contex
    if(!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    BN_print_fp(stdout, prime1);
    printf("\n");

    if(BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("Prime 1 it's a prime\n");
    else
        printf("Prime 1 it is not a prime\n");

    BN_set_word(prime2, 16);

    if(BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("Prime 2 it's a prime\n");
    else
        printf("Prime 2 it is not a prime\n");

    printf("Bits prime 1 = %d\n",BN_num_bytes(prime1));
    printf("Bits prime 2 = %d\n",BN_num_bytes(prime2));

    BN_free(prime1);
    BN_free(prime2);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}