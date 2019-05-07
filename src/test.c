#include "lib.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

//we won't provice any rand or srand ref impl
//make sure your seed is generated safely
//!!! be cafeful !!!!
void gen_seed(unsigned char* seed)
{
    int i = 0;
     //get rand here
    for (i = 0; i < SEED_LEN; i++)
    {
        seed[i] = i + 2;
    }
}

void print_array(unsigned char* array, int len)
{
    int i = 0;
    printf("-----data----------\n");
    for (i = 0; i < len; i++)
    {
        printf("0x%x ", array[i]);
    }
    printf("\n");
}

void test_keypair_from_seed()
{
    unsigned char seed[SEED_LEN] = {0};
    unsigned int rv = STATUS_NOK;
    int i = 0;
    keypair *kp = malloc(sizeof(secret));

    gen_seed(seed);
    printf("-----test keypair_from_seed---------\n");
    rv = keypair_from_seed(seed,&kp);
    assert(rv==STATUS_OK);
    print_array( kp->data,PUB_KEY_LEN + PRI_KEY_LEN);
}

void test_secret_from_seed()
{
    unsigned char seed[SEED_LEN] = {0};
    unsigned int rv = STATUS_NOK;
    int i = 0;
    secret *s = malloc(sizeof(secret));

    gen_seed(seed);
    printf("-----test secret_from_seed---------\n");
    rv = secret_from_seed(seed,&s);
    assert(rv==STATUS_OK);
    print_array( s->data, PRI_KEY_LEN);
}

int main()
{
    test_keypair_from_seed();
    test_secret_from_seed();

    return 0;
}