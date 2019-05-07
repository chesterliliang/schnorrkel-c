#include "lib.h"
#include "string.h"
#include "stdio.h"
#include <stdlib.h>



unsigned int keypair_from_seed(unsigned char* seed, keypair** pair)
{
    unsigned int rv = STATUS_NOK;
    
    memset((*pair)->data, 0x00, PUB_KEY_LEN + PRI_KEY_LEN);
    (*pair)->len = 0;
    (*pair)->status = STATUS_NOK;

    *pair = schnr_keypair_from_seed(seed);
    if ((*pair)->status == STATUS_NOK)
    {
        return STATUS_NOK;
    }

    return STATUS_OK;
}

unsigned int secret_from_seed(unsigned char* seed, secret** s)
{
    unsigned int rv = STATUS_NOK;

    memset((*s)->data, 0x00, PUB_KEY_LEN + PRI_KEY_LEN);
    (*s)->len = 0;
    (*s)->status = STATUS_NOK;

    *s = schnr_secret_from_seed(seed);
    if ((*s)->status == STATUS_NOK)
    {
        return STATUS_NOK;
    }

    return STATUS_OK;
}