#include <stdio.h>
#include <openssl/rand.h>

#define MAX 128

int main(){
    unsigned char random_string[MAX];

    int rc = RAND_load_file("/dev/random", 32); 
    if(rc != 32){
        printf("Couldn't initialize PRNG\n");
        exit(1);
    }

    RAND_bytes(random_string, MAX);

    printf("Sequence generated: ");
    for(int i = 0; i < MAX; i++){
        if(i == MAX -1)
            printf("%02x", random_string[i]);
        else
            printf("%02x-", random_string[i]);
    }
    printf("\n");
    
    return 0;
}
