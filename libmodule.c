#include <ldap.h>
#include <lber.h>

#include "lutil.h"

struct berval *pw_scheme = NULL;
LUTIL_PASSWD_CHK_FUNC *pw_check = NULL;
LUTIL_PASSWD_HASH_FUNC *pw_hash = NULL;

int lutil_passwd_add(
    struct berval *scheme,
    LUTIL_PASSWD_CHK_FUNC *chk,
    LUTIL_PASSWD_HASH_FUNC *hash)
{
    pw_scheme = scheme;
    pw_check = chk;
    pw_hash = hash;

    return(0);
}
