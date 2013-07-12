#include <stdlib.h>
#include <sys/param.h>
#include <unistd.h>
#include <libgen.h>

#include <stdio.h>
#include <dlfcn.h>

#include <lber.h>

#include "lutil.h"

extern struct berval *pw_scheme;
extern LUTIL_PASSWD_CHK_FUNC *pw_check;
extern LUTIL_PASSWD_HASH_FUNC *pw_hash;

int main(int n, char *v[]) {
    int (*init)(int, char **);
    int code;

    void *handle;

    struct berval cred, passwd;

    char *s, path[MAXPATHLEN];

    if (n >= 2) {
	if (*v[1] == '/') {
	    s = v[1];
	} else {
	    if ((s = getcwd(NULL, 0)) == NULL) {
		perror("getcwd(): ");
		exit(0);
	    }

	    memset(path, 0, sizeof(path));

	    snprintf(path, sizeof(path), "%s/%s", s, v[1]);

	    free(s);

	    s = path;
	}

	fprintf(stderr, "Load:\t%s ...\n", s);

	if ((handle = dlopen(s, RTLD_NOW | RTLD_LOCAL)) == NULL) {
	    fprintf(stderr, "%s while loading \"%s\"\n", dlerror(), s);
	} else {
	    if ((init = dlsym(handle, "init_module")) == NULL) {
		fprintf(stderr, "%s while searching for \"%s\" in \"%s\"\n",
		    dlerror(), "init_module", s);
	    } else {
		code = (*init)(0, NULL);

		fprintf(stderr, "Scheme:\t%*s\n", pw_scheme->bv_len, pw_scheme->bv_val);

		if (n >= 4) {
		    passwd.bv_len = strlen(v[2]);
		    passwd.bv_val = v[2];

		    cred.bv_len = strlen(v[3]);
		    cred.bv_val = v[3];

		    code = (*pw_check)(pw_scheme, &passwd, &cred, NULL);

		    fprintf(stderr, "Check:\t%d\n", code);
		}
	    }

	    dlclose(handle);
	}
    }

    exit(0);
}
