#include <ldap.h>
#include <lber.h>

#include <krb5.h>

#include "lutil.h"

/* From <ldap_pvt.h> */
LDAP_F (char *)ldap_pvt_get_fqdn LDAP_P((char *));

static LUTIL_PASSWD_CHK_FUNC chk_kerberos;

#define SCHEME	"{KERBEROS}"

static struct berval scheme = {
    sizeof(SCHEME) - 1,
    SCHEME
};

#include <syslog.h>

static int chk_kerberos(
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

    {
	krb5_context context;
	krb5_error_code ret;
	krb5_creds creds;
	krb5_get_init_creds_opt get_options;
	krb5_verify_init_creds_opt verify_options;
	krb5_principal client, server;

	ret = krb5_init_context( &context );
	if (ret) {
	    return LUTIL_PASSWD_ERR;
	}

	krb5_get_init_creds_opt_init( &get_options );

	krb5_verify_init_creds_opt_init( &verify_options );
    
	ret = krb5_parse_name( context, passwd->bv_val, &client );

	if (ret) {
	    krb5_free_context( context );
	    return LUTIL_PASSWD_ERR;
	}

	ret = krb5_get_init_creds_password( context,
	    &creds, client, cred->bv_val, NULL,
	    NULL, 0, NULL, &get_options );

	if (ret) {
	    krb5_free_principal( context, client );
	    krb5_free_context( context );
	    return LUTIL_PASSWD_ERR;
	}

	{
	    char *host = ldap_pvt_get_fqdn( NULL );

	    if( host == NULL ) {
		krb5_free_principal( context, client );
		krb5_free_context( context );
		return LUTIL_PASSWD_ERR;
	    }

	    ret = krb5_sname_to_principal( context, host,
		"ldap", KRB5_NT_SRV_HST, &server );

	    ber_memfree( host );
	}

	if (ret) {
	    krb5_free_principal( context, client );
	    krb5_free_context( context );
	    return LUTIL_PASSWD_ERR;
	}

	ret = krb5_verify_init_creds( context, &creds,
	    server, NULL, NULL, &verify_options );

	krb5_free_principal( context, client );
	krb5_free_principal( context, server );
	krb5_free_cred_contents( context, &creds );
	krb5_free_context( context );

	if (ret) {
	    return LUTIL_PASSWD_ERR;
	}
    }

    return LUTIL_PASSWD_OK;
}

int init_module(int argc, char *argv[]) {
    return lutil_passwd_add(&scheme, chk_kerberos, NULL);
}
