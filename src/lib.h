#define SEED_LEN        32
#define PUB_KEY_LEN     32
#define PRI_KEY_LEN     64
#define STATUS_OK       0
#define STATUS_NOK      1
#define DATA_BUF_LEN    96
#define SIGN_LEN        64

typedef struct _sr_keypair
{
    unsigned char pri[PRI_KEY_LEN];
    unsigned char pub[PUB_KEY_LEN];
} sr_keypair;


unsigned int keypair_from_seed(unsigned char *seed, sr_keypair *kp);

unsigned int secret_from_seed(unsigned char *seed, unsigned char *secret);

unsigned int sign(unsigned char* puk,unsigned char* pri,unsigned char* msg, unsigned int msg_len, unsigned char* sign);

unsigned int verify(unsigned char* sign, unsigned char* puk, unsigned char* msg, unsigned int msg_len);
