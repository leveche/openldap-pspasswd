#include "base64.h"

#define N	16

typedef struct {
    unsigned long P[N + 2];
    unsigned long S[4][256];
} blf_key;

void blf_ecb_decrypt(blf_key *, unsigned char *, long);
void blf_ecb_encrypt(blf_key *, unsigned char *, long);
void blf_eks_setup(blf_key *, unsigned char *, long,  unsigned char *, long, int);
void blf_init(blf_key *, unsigned char *, long);
