#include <ldap.h>
#include <lber.h>

#include <pwd.h>

#include "lutil.h"

static LUTIL_PASSWD_CHK_FUNC chk_pssblf;

#define PSSBLFSCHEME  "{X-SASBLF}"

static struct berval scheme = {
    sizeof(PSSBLFSCHEME) - 1,
    PSSBLFSCHEME
};

static int chk_pssblf(
    const struct berval *scheme,
    const struct berval *passwd,
    const struct berval *cred,
    const char **text)
{
    int n;

    /* Make sure there are no NULL characters in credentials. */

    for (n = 0; n < cred->bv_len; n += 1) {
	if (cred->bv_val[n] == '\0') {
	    return(LUTIL_PASSWD_ERR);
	}
    }

    /* Make sure that the credentials are NULL terminated. */

    if (cred->bv_val[n] != '\0') {
	    return(LUTIL_PASSWD_ERR);
    }

    /* Make sure there are no NULL characters in password. */

    for (n = 0; n < passwd->bv_len; n += 1) {
	if (passwd->bv_val[n] == '\0') {
	    return(LUTIL_PASSWD_ERR);
	}
    }

    /* Make sure that the password is NULL terminated. */

    if (passwd->bv_val[n] != '\0') {
	return(LUTIL_PASSWD_ERR);
    }

    /* Let's just make sure that the supplied password is the correct length. */

    if (passwd->bv_len != 7 + 22 + 31) {
	return(LUTIL_PASSWD_ERR);
    }

    /* Now compare credentials with BLF-encrypted password. */

    if (strncmp(passwd->bv_val, bcrypt(cred->bv_val, passwd->bv_val), passwd->bv_len)) {
	return(LUTIL_PASSWD_ERR);
    }

    return(LUTIL_PASSWD_OK);
}

int init_module(int argc, char *argv[]) {
    return lutil_passwd_add(&scheme, chk_pssblf, NULL);
}
