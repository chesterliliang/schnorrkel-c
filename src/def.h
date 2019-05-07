#define SEED_LEN 32
#define PUB_KEY_LEN 32
#define PRI_KEY_LEN 64
#define STATUS_OK 0
#define STATUS_NOK 1

typedef struct _keypair
{
    unsigned int status;
    unsigned char data[PUB_KEY_LEN+PRI_KEY_LEN];
    unsigned int len;
}keypair;

typedef struct _secret
{
    unsigned int status;
    unsigned char data[PUB_KEY_LEN+PRI_KEY_LEN];
    unsigned int len;
}secret;

extern keypair* schnr_keypair_from_seed(unsigned char* seed);

extern secret* schnr_secret_from_seed(unsigned char* seed);