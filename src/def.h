#define RUST_PUB_KEY_LEN 32
#define RUST_PRI_KEY_LEN 64

typedef struct _sr_data
{
    unsigned int status;
    unsigned char data[RUST_PUB_KEY_LEN+RUST_PRI_KEY_LEN];
    unsigned int len;
}sr_data;



extern sr_data* schnr_keypair_from_seed(unsigned char* seed);

extern sr_data* schnr_secret_from_seed(unsigned char* seed);