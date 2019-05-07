#include "lib.h"
#include "def.h"
#include "string.h"
#include "stdio.h"
#include <stdlib.h>



unsigned int keypair_from_seed(unsigned char* seed, sr_keypair* kp)
{
    unsigned int rv = STATUS_NOK;
    sr_data *pair = malloc(sizeof(sr_data));
    sr_data** p = &pair;
    memset((*p)->data, 0x00, DATA_BUF_LEN);
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
    sr_data *scr = malloc(sizeof(sr_data));
    sr_data** p = &scr;

    memset((*p)->data, 0x00, DATA_BUF_LEN);
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

unsigned int sign(unsigned char* puk,unsigned char* pri,unsigned char* msg, unsigned int msg_len, unsigned char* sign)
{
    unsigned int rv = STATUS_NOK;
    sr_data *scr = malloc(sizeof(sr_data));
    sr_data** p = &scr;

    memset((*p)->data, 0x00, DATA_BUF_LEN);
    (*p)->len = 0;
    (*p)->status = STATUS_NOK;

    *p = schnr_sign(puk,pri,msg,msg_len);
    if ((*p)->status == STATUS_NOK)
    {
        return STATUS_NOK;
    }

    memcpy(sign,(*p)->data,SIGN_LEN);
    free(scr);

    return STATUS_OK;
}

unsigned int verify(unsigned char* sign, unsigned char* puk, unsigned char* msg, unsigned int msg_len)
{
    unsigned int rv = STATUS_NOK;

    rv = schnr_verify(sign,puk,msg,msg_len);

    return rv;
}