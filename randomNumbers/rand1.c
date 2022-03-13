#include <stdio.h>
#include <openssl/rand.h>

#define MAX 128

int main(){
    unsigned char random_string1[MAX], random_string2[MAX];
    unsigned char output[MAX];

    // RAND_load_file("/dev/random", 64); optional on UNIX enviroment
    RAND_bytes(random_string1, MAX);
    RAND_bytes(random_string2, MAX);

    

    printf("Sequence generated: ");
    for(int i = 0; i < MAX; i++){
        output[i] = random_string1[i]^random_string2[i];
        if(i == MAX - 1)
            printf("%02x", output[i]);
        else
            printf("%02x-", output[i]);
    }
    printf("\n");
    
    return 0;
}
