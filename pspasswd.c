#include <stdlib.h>
#include <errno.h>
#include <pwd.h>

#include <lber.h>
#include <ldap.h>

#include "krb5_pw_validate.c"

static int DEBUG = 0, TEST = 0;

#if ! defined(SERVER)
    #define SERVER	"ldap://127.0.0.1:389"
#endif

static LDAP *ldap = NULL;

/* Print out an error message. */

static void ldapError(int code, char *message, char *extra) {
    if (code) fprintf(stderr, "%s ", ldap_err2string(code));

    fprintf(stderr, "%s\n", (message) ? message : "");

    if (extra && *extra) fprintf(stderr, "    %s", extra);

    return;
}

/* Initialize a connection to an LDAP server. */

static int ldapInitialize(LDAP **ldap, char *server) {
    int code = 0;
    int n;

    /* Open connection to LDAP server. */

    if (code = ldap_initialize(ldap, server) != 0) {
	ldapError(code, "(server unavailable, try later)", NULL);
    } else {

	/* Make sure LDAP version is at level LDAPv3. */

	n = LDAP_VERSION3;

	code = ldap_set_option(*ldap, LDAP_OPT_PROTOCOL_VERSION, &n);

	if (code != LDAP_SUCCESS) {
	    ldapError(code, "while trying to set protocol version", NULL);
	} else {
#if defined(NOVERIFY)
	    n = LDAP_OPT_X_TLS_NEVER;

	    code = ldap_pvt_tls_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
		&n);

	    if (code != LDAP_SUCCESS) {
		    ldapError(code,
			"while trying to disable certificate verification",
			NULL);    
		    return(code);   
	    }
#endif

	    /* Set TLS/SSL prior to authenticating. */

	    code = ldap_start_tls_s(*ldap, NULL, NULL);

	    if (code != LDAP_SUCCESS) {
		ldapError(code, "while trying to set SSL/TLS", NULL);
	    } else {

		/* Authenticate as the master user (at least for now). */

		code = ldap_bind_s(*ldap, "cn=manager,dc=ualberta,dc=ca",
		    "ObSkEwEr", LDAP_AUTH_SIMPLE);

		if (code != LDAP_SUCCESS) {
		    ldapError(code, "while binding to server", NULL);
		}
	    }
	}
    }

    return(code);
}

/* Get space for setting attribute values in LDAP modify request. */

#include <assert.h>

static LDAPMod **getModSpace(int n, ...) {
    LDAPMod **mod = NULL;
    long space, size;
    va_list p;
    int x, y;

    assert(sizeof(void *) == sizeof(long));

    size = n;

    va_start(p, n);

    for (y = 1; (x = va_arg(p, int)) >= 0; y += 1) size += x;

    va_end(p);

    size = ((y + 1) * sizeof(LDAPMod *)) + (y * sizeof(LDAPMod)) +
	((size + y) * sizeof(char *));

    if ((mod = malloc(size)) == NULL) {
	ldapError(0, "No space for LDAPMod data", NULL);
	exit(1);
    }

    memset(mod, 0, size);

    space = (long)&mod[y + 1];

    x = n;

    va_start(p, n);

    for (y = 0; x >= 0; y += 1) {
	mod[y] = (LDAPMod *)space;
	mod[y]->mod_values = (char **)(space + sizeof(LDAPMod));

	space += sizeof(LDAPMod) + ((x + 1) * sizeof(char *));

	x = va_arg(p, int);
    }

    va_end(p);

    assert(space == (long)mod + size);

    return(mod);
}

/*
 *  Find an entry in an array of "berval" structures whose value begins
 *  with a specific character string. Return the array element number
 *  that matches or -1 if none found. if flag is zero, the match must be
 *  exact, otherwise only the first part of the value needs to match the
 *  given string.
 */

static int findValue(struct berval **v, char *s, int flag) {
    int m, n;

    if (flag) m = strlen(s);

    for (n = 0; v[n]; n += 1) {
	if (flag == 0) m = v[n]->bv_len;

	if ((v[n]->bv_len >= m) && (strncasecmp(v[n]->bv_val, s, m) == 0)) {
	    return(n);
	}
    }

    return(-1);
}

/* Table of userPassword types to ignore. */

#define PSKRB5SCHEME	"{x-sakrb5}"
#define PSSBLFSCHEME	"{x-sasblf}"

static char *table[] = {
    "{kerberos}",
    PSKRB5SCHEME,
    PSSBLFSCHEME
};

/*
 *  Check a userPassword value entry to see if it should be ignored based on
 *  whether or not it starts with one of the strings in the table above.
 */

static int ignoreValue(struct berval *v) {
    int m, n;

    for (n = 0; n < sizeof(table)/sizeof(*table); n += 1) {
	m = strlen(table[n]);

	if ((v->bv_len > m) && (strncasecmp(v->bv_val, table[n], m) == 0)) {
	    return(1);
	}
    }

    return(0);
}

/* Print an array of attribute values. */

static printValues(char *s, struct berval **v) {
    int n;

    if (v == NULL) return;

    printf("\n%s: %d\n", s, ldap_count_values_len(v));

    for (n = 0; v[n]; n += 1) {
	printf("    %*s\n", v[n]->bv_len, v[n]->bv_val);
    }

    return;
}

void printMods(LDAPMod **mods) {
    char buffer[1024];
    int m, n;

    for (m = 0; mods[m]; m += 1) {
	snprintf(buffer, sizeof(buffer), "%0X %s", mods[m]->mod_op,
	    mods[m]->mod_type);

	printValues(buffer, &(mods[m]->mod_bvalues[0]));
    }

    return;
}

/* Reset LDAP values so that there is no personal secondary password. */

LDAPMod **unset(char *ccid, char *password, struct berval **os,
    struct berval **up, int shortbus, void **space)
{
    LDAPMod **mods = NULL;
    struct berval *bv;

    int m, n;
    char *s;

    m = ldap_count_values_len(up) + 1;
    n = (shortbus) ? ((os) ? ldap_count_values_len(os) : 0) : 0;

    mods = getModSpace(m, n, -1);

    if ((*space = malloc(sizeof(struct berval) + 256)) == NULL) {
	ldapError(0, "No space for new password values", NULL);
	exit(1);
    }

    bv = (struct berval *)*space;

    s = (char *)&bv[1];

    snprintf(s, 256, "{kerberos}%s@UALBERTA.CA", ccid);
    bv[0].bv_len = strlen(s);
    bv[0].bv_val = s;

    mods[0]->mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mods[0]->mod_type = "userPassword";

    mods[0]->mod_bvalues[0] = &bv[0];

    m = 1;

    for (n = 0; up[n]; n += 1) {
	if (ignoreValue(up[n]) == 0) {
	    mods[0]->mod_bvalues[m++] = up[n];
	}
    }

    if ((shortbus == 0) || (os == NULL)) {
	mods[1] = NULL;
    } else {
	mods[1]->mod_op = LDAP_MOD_BVALUES;
	mods[1]->mod_type = "organizationalStatus";

	m = 0;

	for (n = 0; os[n]; n += 1) {
	    if (strncasecmp(os[n]->bv_val, "psp", os[n]->bv_len)) {
		mods[1]->mod_bvalues[m++] = os[n];
	    }
	}

	mods[1]->mod_op |= (m) ? LDAP_MOD_REPLACE : LDAP_MOD_DELETE;
    }

    return(mods);
}

/* Set the personal secondary password values in LDAP. */

LDAPMod **set(char *ccid, char *password, struct berval **os,
    struct berval **up, int shortbus, void **space)
{
    LDAPMod **mods = NULL;
    struct berval *bv;

    int m, n;
    char *s;

    m = ldap_count_values_len(up) + 2;
    n = (shortbus) ? 0 : ((os) ? ldap_count_values_len(os) + 1 : 1);

    mods = getModSpace(m, n, -1);

    if ((*space = malloc((sizeof(struct berval) * 3) + (256 * 2))) == NULL) {
	ldapError(0, "No space for new password values", NULL);
	exit(1);
    }

    bv = (struct berval *)*space;

    s = (char *)&bv[3];

    snprintf(s, 256, "%s%s@UALBERTA.CA", PSKRB5SCHEME, ccid);
    bv[0].bv_len = strlen(s);
    bv[0].bv_val = s;

    s = &s[256];

    snprintf(s, 256, "%s%s", PSSBLFSCHEME, bcrypt(password, bcrypt_gensalt(8)));
    bv[1].bv_len = strlen(s);
    bv[1].bv_val = s;

    mods[0]->mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mods[0]->mod_type = "userPassword";

    mods[0]->mod_bvalues[0] = &bv[0];
    mods[0]->mod_bvalues[1] = &bv[1];

    m = 2;

    for (n = 0; up[n]; n += 1) {
	if (ignoreValue(up[n]) == 0) {
	    mods[0]->mod_bvalues[m++] = up[n];
	}
    }

    if (shortbus) {
	mods[1] = NULL;
    } else {
	mods[1]->mod_op = ((os) ? LDAP_MOD_REPLACE : LDAP_MOD_ADD) |
	    LDAP_MOD_BVALUES;
	mods[1]->mod_type = "organizationalStatus";

	bv[2].bv_len = strlen("psp");
	bv[2].bv_val = "psp";

	mods[1]->mod_bvalues[0] = &bv[2];

	if (os) {
	    for (n = 0; os[n]; n += 1) {
		if (strncasecmp(os[n]->bv_val, "psp", os[n]->bv_len)) {
		    mods[1]->mod_bvalues[m++] = os[n];
		}
	    }
	}
    }

    return(mods);
}

/* Main program. */

static struct options {
    char    *command;
    LDAPMod **(*function)();
    int	    arguments;
} options[] = {
    { "unset", &unset, 3 }, 
    { "set",   &set,   4 },
};

int main(int n, char *v[]) {

    /* List of attributes for which to search. */

    char *attrs[] = { "organizationalstatus", "userpassword", NULL };

    char *ccid = NULL, *newpw = NULL, *oldpw = NULL;
    char buffer[1024], dn[1024];
    char *s;

    void *space = NULL;

    int shortbus = 0;
    int force = 0;
    int code = 0;
    int m;

    LDAPMod **(*option)() = NULL;
    LDAPMod **mods = NULL;

    LDAPMessage *result;
    LDAPMessage *e;

    struct berval **os, **up;

    /* Allow for debugging and testing. */

    if (s = getenv("DEBUG")) DEBUG = atol(s);
    if (s = getenv("TEST")) TEST = atol(s);

    /* Check arguments to program. */

    if (n <= 1) {
	fprintf(stderr, "usage: %s <option> <ccid> <oldpwd> <newpwd>\n", v[0]);
	exit(1);
    }

    if (strncasecmp("force", v[1], strlen(v[1])) == 0) {
	option = &set;
	m = 4;
	force = 1;
    } else {
	for (m = 0; m < sizeof(options) / sizeof(struct options); m += 1) {
	    if (strncasecmp(v[1], options[m].command, strlen(v[1])) == 0) {
		option = options[m].function;
		m = options[m].arguments;
		break;
	    }
	}
    }

    if (option == NULL) {
	fprintf(stderr, "%s: no such <option>\n", v[1]);
	exit(1);
    }

    if (n <= m) {
	fprintf(stderr, "usage: %s <option> <ccid> <oldpwd> <newpwd>\n", v[0]);
	exit(1);
    }

    if (m >= 2) ccid = v[2];
    if (m >= 3) oldpw = v[3];
    if (m >= 4) newpw = v[4];

    /* Initialize the LDAP connection. */

    if (ldapInitialize(&ldap, SERVER) == LDAP_SUCCESS) {

	/* Set the DN for the user in question. */

	snprintf(dn, sizeof(dn), "uid=%s,ou=people,dc=ualberta,dc=ca", ccid);

	/* Search for required attributes associated with desired user. */

	code = ldap_search_s(ldap, dn, LDAP_SCOPE_BASE, "(objectclass=*)",
	    attrs, 0, &result);

	if (code != LDAP_SUCCESS) {
	    ldapError(code, "while performing search for required attributes",
		NULL);
	} else {

	    /* Check whether the proper number of results were returned. */

	    if ((m = ldap_count_entries(ldap, result)) != 1) {
		snprintf(buffer, sizeof(buffer),
		    "Search returned incorrect number of entries: %d", m);
		ldapError(0, buffer, NULL);
	    } else {

		/* Get the first (and only) returned LDAP node entry. */

		e = ldap_first_entry(ldap, result);

		/* Get any values associated with "organizationalStatus". */

		os = ldap_get_values_len(ldap, e, "organizationalstatus");

		if (os == NULL) {
		    if (DEBUG)
			ldapError(0,
			    "No values found for organizationalstatus", NULL);
		} else {
		    if (DEBUG) printValues("organizationalStatus", os);

		    /* Scan the returned values to see if "psp" is set. */

		    if (findValue(os, "psp", 0) >= 0) {
			shortbus = 1;
		    }
		}

		/* Get any values associated with "userPassword". */

		up = ldap_get_values_len(ldap, e, "userpassword");

		if (up == NULL) {
		    ldapError(0, "Internal error: no password values found",
			NULL);
		} else {
		    if (DEBUG) printValues("userPassword", up);

		    if (force == 0) {
			if (shortbus == 0) {
			    if (option != &set) {
				printf("Secondary password incorrect\n");
				code = -1;
			    } else {
				code = krb5_pw_validate(ccid, oldpw, NULL, NULL,
				    NULL);

				if (code) {
				    printf("Kerberos password incorrect\n");
				}
			    }
			} else {
			    code = -1;

			    if ((m = findValue(up, PSSBLFSCHEME, 1)) < 0) {
				printf("Internal error: no secondary password\n");
			    } else {
				s = &(up[m]->bv_val[10]);

				if (strncmp(s, bcrypt(oldpw, s), strlen(s))) {
				    printf("Secondary password incorrect\n");
				} else {
				    code = 0;
				}
			    }
			}
		    }

		    if (code == 0) {
			if (krb5_pw_validate(ccid, newpw, NULL, NULL, NULL) == 0) {
			    printf("Secondary and Kerberos passwords are the same\n");
			} else {
			    mods = (*option)(ccid, newpw, os, up, shortbus,
				&space);

			    if (TEST) {
				printMods(mods);
			    } else {
				if (DEBUG) printMods(mods);

				code = ldap_modify_s(ldap, dn, mods);

				if (code) {
				    ldapError(code,
					"while changing password", NULL);
				} else {
				    printf("Password changed\n");
				}
			    }

			    free(space);
			    free(mods);
			}
		    }
		}

		if (up) ldap_value_free_len(up);
		if (os) ldap_value_free_len(os);
	    }

	    ldap_msgfree(result);
	}

	ldap_unbind_s(ldap);
    }
}
