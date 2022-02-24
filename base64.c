/*
    (From draft-ietf-dnssec-secext-04.txt)

    The following encoding technique is taken from RFC 1521 by Borenstein
    and Freed.  It is reproduced here in an edited form for convenience.

    A 65-character subset of US-ASCII is used, enabling 6 bits to be
    represented per printable character. (The extra 65th character, "=",
    is used to signify a special processing function.)

    The encoding process represents 24-bit groups of input bits as output
    strings of 4 encoded characters. Proceeding from left to right, a
    24-bit input group is formed by concatenating 3 8-bit input groups.
    These 24 bits are then treated as 4 concatenated 6-bit groups, each
    of which is translated into a single digit in the base64 alphabet.

    Each 6-bit group is used as an index into an array of 64 printable
    characters. The character referenced by the index is placed in the
    output string.

                          Table 1: The Base64 Alphabet

       Value Encoding  Value Encoding  Value Encoding  Value Encoding
           0 A            17 R            34 i            51 z
           1 B            18 S            35 j            52 0
           2 C            19 T            36 k            53 1
           3 D            20 U            37 l            54 2
           4 E            21 V            38 m            55 3
           5 F            22 W            39 n            56 4
           6 G            23 X            40 o            57 5
           7 H            24 Y            41 p            58 6
           8 I            25 Z            42 q            59 7
           9 J            26 a            43 r            60 8
          10 K            27 b            44 s            61 9
          11 L            28 c            45 t            62 +
          12 M            29 d            46 u            63 /
          13 N            30 e            47 v
          14 O            31 f            48 w         (pad) =
          15 P            32 g            49 x
          16 Q            33 h            50 y

    Special processing is performed if fewer than 24 bits are available
    at the end of the data being encoded.  A full encoding quantum is
    always completed at the end of a quantity.  When fewer than 24 input
    bits are available in an input group, zero bits are added (on the
    right) to form an integral number of 6-bit groups.  Padding at the
    end of the data is performed using the '=' character.  Since all
    base64 input is an integral number of octets, only the following
    cases can arise: (1) the final quantum of encoding input is an
    integral multiple of 24 bits; here, the final unit of encoded output
    will be an integral multiple of 4 characters with no "=" padding, (2)
    the final quantum of encoding input is exactly 8 bits; here, the
    final unit of encoded output will be two characters followed by two
    "=" padding characters, or (3) the final quantum of encoding input is
    exactly 16 bits; here, the final unit of encoded output will be three
    characters followed by one "=" padding character.
*/

#include <string.h>
#include <stdlib.h>
#include <errno.h>

static const char Encode64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

#define Pad64	Encode64[64]

int Base64Encode(unsigned char *src, long srclen, char *dst, long dstlen, char *table) {
    unsigned char *d, *e, *s;
    long n, m;

    if (table == NULL) table = (char *)Encode64;

    errno = EINVAL;

    if ((n = ((srclen + 2) / 3) * 4) >= dstlen) return(-1);

    errno = 0;

#if defined(OVERLAP)
    if ((s = malloc(srclen)) == NULL) return(-1);

    memcpy(s, src, srclen);

    src = s;
#endif

    memset(dst + n, 0, dstlen - n);

    s = (unsigned char *)src;
    e = s + srclen;

    d = (unsigned char *)dst;

    while ((e - s) > 2) {
	m = (s[0] << 16) | (s[1] << 8) | s[2];

	d[0] = table[(m >> 18) & 0x3f];
	d[1] = table[(m >> 12) & 0x3f];
	d[2] = table[(m >> 6) & 0x3f];
	d[3] = table[m & 0x3f];

	d += 4;
	s += 3;
    }

    if (s < e) {
	m = s[0] << 16;

	d[0] = table[(m >> 18) & 0x3f];

	if ((e - s) == 2) {
	    m |= (s[1] << 8);
	    d[2] = table[(m >> 6) & 0x3f];
	} else {
	    d[2] = table[64];
	}

	d[1] = table[(m >> 12) & 0x3f];
	d[3] = table[64];

	if (table[64] == 0) n -= (3 - (e - s));
    }

#if defined(OVERLAP)
    free(src);
#endif

    return(n);
}

static const char Decode64[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

int Base64Decode(char *src, unsigned char *dst, long dstlen, char *table) {
    char *decode, buffer[256];
    unsigned char *d, *e, *s;
    long m, n;

#if defined(OVERLAP)
    unsigned char *t;
#endif

    if (table == NULL) {
	decode = (char *)Decode64;
	table = (char *)Encode64;
    } else {
	memset(decode = buffer, -1, sizeof(buffer));

	for (n = 0; n < 64; n += 1) {
	    decode[(int)table[n]] = n;
	}
    }

    errno = EINVAL;

    s = (unsigned char *)src;

    for (e = s; (*e != 0) && (*e != table[64]); e += 1) {
	if (decode[*e] < 0) return(-1);
    }

    if (table[64] == 0) {
	n = (((e - s + 3) / 4) * 4) - (e - s);
    } else {
	if ((n = ((e[0] == table[64]) ? 1 : 0))) {
	    if (e[1] == table[64]) n = 2;
	}

	if ((e[n]) || ((e - s + n) % 4)) return(-1);
    }

    if (((n = (((e - s + n) / 4) * 3) - n) > dstlen)) return(-1);

    errno = 0;

    d = (unsigned char *)dst;

#if defined(OVERLAP)
    if ((t = malloc(n)) == NULL) return(-1);

    d = t;
#endif

    while ((e - s) > 3) {
	m = (decode[s[0]] << 18) | (decode[s[1]] << 12) |
	    (decode[s[2]] << 6) | decode[s[3]];

	d[0] = (m >> 16) & 0xff;
	d[1] = (m >> 8) & 0xff;
	d[2] = m & 0xff;

	d += 3;
	s += 4;
    }

    if (s < e) {
	m = (decode[s[0]] << 18) | (decode[s[1]] << 12);

	d[0] = (m >> 16) & 0xff;

	if ((e - s) == 3) {
	    m |= (decode[s[2]] << 6);
	    d[1] = (m >> 8) & 0xff;
	}
    }

    memset(dst + n, 0, dstlen - n);

#if defined(OVERLAP)
    memcpy(dst, t, n);

    free(t);
#endif

    return(n);
}

#if defined(TEST)

#include <stdio.h>
#include <string.h>

int main(int n, char *v[]) {
    unsigned char *e, encode[1024];
    char *d, decode[1024];
    int m;

    for (n -= 1; n; n -= 1) {
#if defined(OVERLAP)
	d = decode + 5;
	strncpy(d, v[n], sizeof(decode) - (d - decode));
#else
	d = v[n];
#endif
	
	printf("encode: %s [%s", v[n], d);

	if ((m = Base64Encode((unsigned char *)d, strlen(d), decode,
	    sizeof(decode), NULL)) < 0) {
	    perror("encode");
	} else {
	    printf(" <> %s] => [%d] %s\n", d, m, decode);
	}

#if defined(OVERLAP)
	e = encode + 3;
	strncpy((char *)e, decode, sizeof(encode) - (e - encode));
#else
	e = (unsigned char *)decode;
#endif
	
	printf("decode: %s [%s", decode, e);

	if ((m = Base64Decode((char *)e, encode, sizeof(encode), NULL)) < 0) {
	    perror("decode");
	} else {
	    printf(" <> %s] => [%d] %s\n", e, m, encode);
	}
    }

    exit(0);
}

#else
#if defined(MAIN)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

void usage(char *program) {
    printf("usage: %s {-d[ecode] | -e[ncode]}\n", program);
    return;
}

long readbuffer(int f, unsigned char *buffer, long n) {
    unsigned char *s = buffer;
    long m;

    while ((n > 0) && ((m = read(f, s, n)) > 0)) {
	s += m;
	n -= m;
    }

    return(s - buffer);
}

int main(int n, char *v[]) {
    unsigned char encode[768];
    char decode[1025];
    int m;

    if (n != 2) {
	usage(v[0]);
	exit(1);
    }

    if (strncmp(v[1], "-encode", strlen(v[1])) == 0) {
	while ((n = readbuffer(0, encode, 60)) > 0) {
	    if ((m = Base64Encode(encode, n, decode, sizeof(decode), NULL)) < 0) {
		perror("encode");
		exit(1);
	    }

	    printf("%s\n", decode);
	}
    } else if (strncmp(v[1], "-decode", strlen(v[1])) == 0) {
	for (;;) {
	    n = 0;
	    while (n < sizeof(decode) - 1) {
		if ((m = getc(stdin)) == EOF) break;
		if (! isspace(m)) decode[n++] = m;
	    }
	    decode[n] = 0;

	    if (n == 0) break;

	    if ((m = Base64Decode(decode, encode, sizeof(encode), NULL)) < 0) {
		perror("decode");
		exit(1);
	    }

	    write(1, encode, m);
	}
    } else {
	usage(v[0]);
	exit(1);
    }

    exit(0);
}

#endif
#endif
