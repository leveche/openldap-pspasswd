#include <ldap.h>
#include <lber.h>

#include <krb5.h>

#include "lutil.h"

#include "krb5_pw_validate.c"

LDAP_F (char *)ldap_pvt_get_fqdn LDAP_P((char *));

static LUTIL_PASSWD_CHK_FUNC chk_pskrb5;

#define PSKRB5SCHEME	"{X-SAKRB5}"

static struct berval scheme = {
    sizeof(PSKRB5SCHEME) - 1,      
    PSKRB5SCHEME
};

static int chk_pskrb5(
    const struct berval *scheme,
    const struct berval *passwd,
    const struct berval *cred,
    const char **text)
{
    char *host;
    int n;

    krb5_error_code code = 0;

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

    host = ldap_pvt_get_fqdn( NULL );

    if (host == NULL) {
        return(LUTIL_PASSWD_ERR);
    }

    code = krb5_pw_validate(passwd->bv_val, cred->bv_val, "ldap",
	host, NULL);

    ber_memfree(host);

    return((code) ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK);
}

int init_module(int argc, char *argv[]) {
    return lutil_passwd_add(&scheme, chk_pskrb5, NULL);
}
