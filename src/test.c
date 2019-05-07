#include "lib.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

sr_keypair pair;
unsigned char s[SIGN_LEN] = { 0 };
unsigned char msg[32] = {0};

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

    gen_seed(seed);
    printf("-----test keypair_from_seed---------\n");
    rv = keypair_from_seed(seed,&pair);
    assert(rv==STATUS_OK);
    print_array( pair.pri,PRI_KEY_LEN);
    print_array( pair.pub,PUB_KEY_LEN );
}

void test_secret_from_seed()
{
    unsigned char seed[SEED_LEN] = {0};
    unsigned int rv = STATUS_NOK;
    unsigned char s[PRI_KEY_LEN] = { 0 };

    gen_seed(seed);
    printf("-----test secret_from_seed---------\n");
    rv = secret_from_seed(seed,s);
    assert(rv==STATUS_OK);
    print_array( s, PRI_KEY_LEN);
}

void test_sign()
{

    unsigned int rv = STATUS_NOK;
    
    gen_seed(msg);
    printf("-----test sign---------\n");
    rv = sign(pair.pub,pair.pri,msg,32,s);
    assert(rv==STATUS_OK);
    print_array( s, SIGN_LEN);
}

void test_verify()
{
    unsigned int rv = STATUS_NOK;
    printf("-----test verify normal---------\n");
    print_array( s, SIGN_LEN);
    rv = verify(s,pair.pub,msg,32);
    printf("-----rv=%d-------\n",rv);
    if(rv)
        printf("-----verify success--------\n");
    else
        printf("-----verify fail--------\n");

    printf("-----test verify modify---------\n");
    msg[0] = 0xff;
    rv = verify(s,pair.pub,msg,32);
    if(rv)
        printf("-----verify success--------\n");
    else
        printf("-----verify fail--------\n");
}

int main()
{
    test_keypair_from_seed();
    test_secret_from_seed();
    test_sign();
    test_verify();

    return 0;
}