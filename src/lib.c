#include "lib.h"
#include "string.h"
#include "stdio.h"
#include <stdlib.h>



unsigned int keypair_from_seed(unsigned char* seed, sr_keypair* kp)
{
    unsigned int rv = STATUS_NOK;
    keypair *pair = malloc(sizeof(secret));
    keypair** p = &pair;
    memset((*p)->data, 0x00, PUB_KEY_LEN + PRI_KEY_LEN);
    (*p)->len = 0;
    (*p)->status = STATUS_NOK;

    *p = schnr_keypair_from_seed(seed);
    if ((*p)->status == STATUS_NOK)
    {
        return STATUS_NOK;
    }
    memcpy(kp->pri,(*p)->data,PRI_KEY_LEN);
    memcpy(kp->pub,(*p)->data+PRI_KEY_LEN,PUB_KEY_LEN);

    free(pair);

    return STATUS_OK;
}

unsigned int secret_from_seed(unsigned char* seed, unsigned char *s)
{
    unsigned int rv = STATUS_NOK;
    secret *scr = malloc(sizeof(secret));
    secret** p = &scr;

    memset((*p)->data, 0x00, PUB_KEY_LEN + PRI_KEY_LEN);
    (*p)->len = 0;
    (*p)->status = STATUS_NOK;

    *p = schnr_secret_from_seed(seed);
    if ((*p)->status == STATUS_NOK)
    {
        return STATUS_NOK;
    }
    
    memcpy(s,(*p)->data,PRI_KEY_LEN);
    free(scr);

    return STATUS_OK;
}