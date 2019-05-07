#include "def.h"

typedef struct _sr_keypair
{
    unsigned char pri[PRI_KEY_LEN];
    unsigned char pub[PUB_KEY_LEN];
} sr_keypair;


unsigned int keypair_from_seed(unsigned char *seed, sr_keypair *kp);

unsigned int secret_from_seed(unsigned char *seed, unsigned char *secret);