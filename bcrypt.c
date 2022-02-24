#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/rand.h>
#include <openssl/rand.h>

#include "blf.h"

#define BCRYPT_BLOCKS		6
#define BCRYPT_MINLOGROUNDS	4
#define BCRYPT_MINROUNDS	(1 << BCRYPT_MINLOGROUNDS)
#define BCRYPT_VERSION		'2'

#define SALT_MAXLEN	16

static char Base64Code [] =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#define SALTLEN	((((SALT_MAXLEN + 2) / 3) * 4) + 7)

char *bcrypt_gensalt(unsigned char n) {
    static char salt[SALTLEN + 1];

    unsigned char seed[SALT_MAXLEN];
    long m;

    if (n < BCRYPT_MINLOGROUNDS) n = BCRYPT_MINLOGROUNDS;

    if (RAND_bytes(seed, sizeof(seed)) <= 0) {
	fprintf(stderr, "RAND error: %s\n", ERR_error_string(ERR_get_error(),
	    NULL));
	exit(1);
    }

    m = snprintf(salt, sizeof(salt), "$%ca$%2.2u$", BCRYPT_VERSION, n);

    Base64Encode(seed, SALT_MAXLEN, &salt[m], sizeof(salt) - m, Base64Code);

    return(salt);
}

#define HASHLEN	(SALTLEN + (((BCRYPT_BLOCKS * 4 - 1 + 2) / 3) * 4))

char *bcrypt(const char *password, const char *salt) {
    static char hash[HASHLEN + 1];

    unsigned char ciphertext[BCRYPT_BLOCKS * 4] = "OrpheanBeholderScryDoubt";
    unsigned char buffer[SALT_MAXLEN];
    char minor, *s = (char *)salt;
    long m, n, rounds;
    blf_key context;

    errno = EINVAL;

    if (*s++ != '$') return(NULL);

    if (*s++ > BCRYPT_VERSION) return(NULL);

    if (*s == '$') {
	minor = 0;
    } else {
	if (*s++ != 'a') return(NULL);
	minor = 'a';
    }

    if ((*s++ != '$') || (s[2] != '$')) return(NULL);

    if ((rounds = (1 << atoi(s))) < BCRYPT_MINROUNDS) return(NULL);

    if (((strlen(s += 3) * 3) / 4) != SALT_MAXLEN) return(NULL);

    errno = 0;

    Base64Decode(s, buffer, SALT_MAXLEN, Base64Code);

    n = strlen(password) + ((minor >= 'a') ? 1 : 0);

    blf_eks_setup(&context, buffer, SALT_MAXLEN, (unsigned char *)password, n, rounds);

    for (m = 0; m < 64; m += 1)
	blf_ecb_encrypt(&context, ciphertext, BCRYPT_BLOCKS * 4);

    n = snprintf(hash, sizeof(hash), "%s", salt);

    Base64Encode(ciphertext, BCRYPT_BLOCKS * 4 - 1, &hash[n], sizeof(hash) - n,
	Base64Code);

    return(hash);
}

char *blfhash(const char *password, const int n) {
    return(bcrypt(password, bcrypt_gensalt(n)));
}
