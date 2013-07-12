#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

#include <krb5.h>

/* krb5_pw_validate:                                                     */
/*                                                                       */
/* Routine to verify a password using Kerberos 5 and, optionally, verify */
/* the KDC if the password is correct.                                   */
/*                                                                       */
/* Returns the Kerberos 5 error code (zero if successful).               */
/*                                                                       */
/* Parameters:                                                           */
/*                                                                       */
/*    user     = Kerberos 5 user (principal) to validate                 */
/*    password = password to validate                                    */
/*    service  = service used to verify the KDC (or NULL)                */
/*    host     = host used to verify the KDC (or NULL)                   */
/*    file     = keytab file used to verify the KDC (or NULL)            */
/*                                                                       */
/* If service or host is NULL, then the KDC is NOT verified. Otherwise,  */
/* the KDC is verified using service/host@<REALM> where <REALM> is the   */
/* local Kerberos realm. If file is NULL, the default system keytab file */
/* is used.                                                              */
/*                                                                       */
/* The user and password parameters may not be NULL.                     */

int krb5_pw_validate(char *user, char *password, char *service,
    char *host, char *file)
{
    krb5_verify_init_creds_opt verify;
    krb5_get_init_creds_opt options;
    krb5_principal principal;
    krb5_creds credentials;
    krb5_principal server;
    krb5_context context;
    krb5_keytab keytab;

    krb5_error_code code = 0;

#if defined(DEBUG)
    char *s = NULL;
#endif

    /* Check for inappropriate parameters. */

    if ((password == NULL) || (*password == '\0')) return(EINVAL);
    if ((user == NULL) || (*user == '\0')) return(EINVAL);

    /* Initialize Kerberos. */

    if (code = krb5_init_context(&context)) {
	return(code);
    }

    /* Get principal for user. */

    if (code = krb5_parse_name(context, user, &principal)) {
	krb5_free_context(context);
	return(code);
    }

#if defined(DEBUG)
    if (krb5_unparse_name(context, principal, &s) == 0) {
	fprintf(stderr, "Authenticating %s ...\n", s);
	free(s);
    }
#endif

    /* Set Kerberos options. */

    krb5_get_init_creds_opt_init(&options);
    krb5_get_init_creds_opt_set_tkt_life(&options, 1 * 60);
    krb5_get_init_creds_opt_set_renew_life(&options, 0);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);

    /* Initialize credentials. */

    memset(&credentials, 0, sizeof(credentials));

    /* Get ticket-granting ticket, no prompting for password. */

    code = krb5_get_init_creds_password(context, &credentials, principal,
	password, NULL, NULL, 0, NULL, &options);

    if (code == KRB5KDC_ERR_KEY_EXP) {

	/* Expired password. Try again with "change password" service. */
	/* If it works this time, the password is actually correct so  */
	/* return "expired password". Otherwise, return whatever was   */
	/* returned by Kerberos (likely "bad password").               */

	code = krb5_get_init_creds_password(context, &credentials, principal,
	    password, NULL, NULL, 0, "kadmin/changepw", &options);

	if (code == 0) {
	    krb5_free_cred_contents(context, &credentials);

	    code = KRB5KDC_ERR_KEY_EXP;
	}
    } else if (code == 0) {

	/* Password was OK. See if KDC needs to be verified. */

	if (service != NULL) {

	    /* Verify validity of the KDC. */

	    krb5_verify_init_creds_opt_init(&verify);
	    krb5_verify_init_creds_opt_set_ap_req_nofail(&verify, 1);

	    /* Get principal for service. */

	    code = krb5_sname_to_principal(context, host, service,
		KRB5_NT_SRV_HST, &server);

	    if (code == 0) {
#if defined(DEBUG)
		if (krb5_unparse_name(context, server, &s) == 0) {
		    fprintf(stderr, "Validating %s ...\n", s);
		    free(s);
		}
#endif

		/* Set appropriate keytab file. */

		if (file != NULL) {
		    code = krb5_kt_resolve(context, file, &keytab);
		} else {
		    code = krb5_kt_default(context, &keytab);
		}

		if (code == 0) {

		    /* Verify the credentials using the service principal. */

		    code = krb5_verify_init_creds(context, &credentials, server,
		        keytab, NULL, &verify);
		}

		krb5_free_principal(context, server);
	    }
	}

	krb5_free_cred_contents(context, &credentials);
    }

    /* Success or failure now known. */

    krb5_free_principal(context, principal);
    krb5_free_context(context);

    return(code);
}

#ifdef MAIN
#include <com_err.h>

#include <pwd.h>
#include <unistd.h>

int main(n, v) int n; char **v; {
    char *user = NULL, *password = NULL, *service = NULL, *host = NULL;
    char *file = NULL;
    char *s;

    if (n < 2) {
        printf("Usage: %s <user> [<service> [<host> [<keytab>]]]\n", v[0]);
        exit(-1); 
    }

    user = v[1];     

    if (n > 2) {
        service = v[2];
	if (n > 3) {
            host = v[3];

	    if (n > 4) {
		file = v[4];
	    }
	}
    }

    password = getpass("Password: ");

    initialize_krb5_error_table();

    if ((n = krb5_pw_validate(user, password, service, host, file)) == 0)
        printf("Authentication OK\n");
    else {
        s = (n == KRB5KRB_AP_ERR_BAD_INTEGRITY) ? "Password incorrect" :
	     (char *)error_message(n);

        printf("Authentication failed: %s.\n", s);
    }

    exit((n) ? 1 : 0);
}
#endif
