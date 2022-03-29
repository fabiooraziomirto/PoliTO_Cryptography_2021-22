#include <openssl/bn.h>
#include <openssl/err.h>

int main()
{
    // a newly instantiated BIGNUM is initialized to 0
    BIGNUM *a=BN_new();
    BN_hex2bn(&a, "11111111111111111111111111111111");
    
    
    BIGNUM *b=BN_new();
    BN_hex2bn(&b, "22222222222222222222222222222222");

    // add two numbers
    BIGNUM *res=BN_new();
    BIGNUM *res1=BN_new();
    BN_add(res,a,b);
    // BN_add(a,a,b);
    BN_print_fp(stdout,res);
    printf("%d\n",BN_get_word(res));

    //subtraction
    BIGNUM *c=BN_new();
    BN_hex2bn(&c, "3333");


    // integer division
    BIGNUM *d=BN_new();
    BN_hex2bn(&d, "12341234123412341234");



    // a context is needed to optimize some operations
    BN_CTX *ctx=BN_CTX_new();


    // a^b mod m
    BN_mod_exp(res1,res,c,d,ctx);

    BN_print_fp(stdout,res1);


  return 0;
}