/* Taken from OpenLDAP's "lutil.h" file. */

#define LUTIL_PASSWD_ERR	(-1)
#define LUTIL_PASSWD_OK		(0)

#define LDAP_LUTIL_F(type)	extern type

typedef int (LUTIL_PASSWD_CHK_FUNC)(
    const struct berval *scheme,
    const struct berval *passwd,
    const struct berval *cred,
    const char **text);

typedef int (LUTIL_PASSWD_HASH_FUNC) (
    const struct berval *scheme,
    const struct berval *passwd,
    struct berval *hash,
    const char **text);

LDAP_LUTIL_F (int)lutil_passwd_add LDAP_P((
    struct berval *scheme,
    LUTIL_PASSWD_CHK_FUNC *chk,
    LUTIL_PASSWD_HASH_FUNC *hash));
