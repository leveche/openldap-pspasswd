PROGRAMS=	pspasswd module krb5_pw_validate

PROGRAM=	pspasswd

VERSION=	1
REVISION=       0

MODULES=	kerberos.so pskrb5.so pssblf.so

CFLAGS=		-g -I/usr/include/kerberosV -I/usr/local/include
LIBS=		-L/usr/local/lib -R/usr/local/lib -lldap -llber

LIBTOOL=	/usr/local/bin/libtool
LIBTOOL=	./libtool

PREFIX=		/usr/local
BINDIR=		${DESTDIR}${PREFIX}/sbin
LIBDIR=		${DESTDIR}${PREFIX}/lib
LIBEXEC=	${DESTDIR}${PREFIX}/libexec

MODULEFLAGS=	-shared
#MODULEFLAGS=	-Bshareable

SERVER=		"\"ldap://142.244.33.23:389\""
SERVER=		"\"ldap://ldap1.srv.ualberta.ca\""

all:	${PROGRAMS} ${MODULES}

pspasswd:	$@.c krb5_pw_validate.c
	cc -o $@ $@.c -DSERVER=${SERVER} -DNOVERIFY ${CFLAGS} ${LIBS}

module:		module.c libmodule.so
	cc -g -o module module.c -I/usr/local/include -L. -R. -lmodule ${LIBS}

libmodule.so:	libmodule.lo
	${LIBTOOL} --mode=link ${CC} ${CFLAGS} ${MODULEFLAGS} -o $@ libmodule.lo \
		-module

krb5_pw_validate : $@.c
	cc -o $@ $@.c -DMAIN ${CFLAGS} -lkrb5 -lcrypto -lcom_err

pskrb5.so:	krb5_pw_validate.c

install:	all
	@echo "Making install in $(PWD)"
	@mkdir -p ${BINDIR}
	@mkdir -p ${LIBEXEC}/openldap
	@${LIBTOOL} --mode=install ${INSTALL} -c -m 555 ${PROGRAM} ${BINDIR}/${PROGRAM}
	@for m in ${MODULES} ; do \
		${LIBTOOL} --mode=install ${INSTALL} -c -m 444 $$m ${LIBEXEC}/openldap/pw-$$m ;\
	done

clean:
	${LIBTOOL} --mode=clean rm -fr *.la *.lo *.o *.so *.core
	rm -f ${PROGRAMS} module *.o *.core
	rm -f OpenBSD/pspasswd-${VERSION}.${REVISION}.tgz

package:	openbsd

openbsd:	all
	@rm -f OpenBSD/pspasswd-${VERSION}.${REVISION}.tgz
	@make install DESTDIR=/tmp/pkg
	@pkg_create -v -x -d OpenBSD/DESC -f OpenBSD/PLIST -B /tmp/pkg -p /usr/local \
		-D COMMENT='OpenLDAP Kerberos 5 and personal secondary password support' \
		-D MAINTAINER='Antoine Verheijen <antoine@verheijen.ca>' \
		OpenBSD/pspasswd-${VERSION}.${REVISION}.tgz
	@rm -fr /tmp/pkg

tar:	clean
	( set -- `basename \`pwd\`` ; cd .. ; find ./$$1 | sort | \
		cpio -o -z -H ustar -O $$1.tar.gz )

.SUFFIXES:	.c .lo .so

.c.lo:
	${LIBTOOL} --tag=disable-static --mode=compile ${CC} ${CFLAGS} -c $<

.lo.so:
	${LIBTOOL} --mode=link ${CC} ${CFLAGS} ${MODULEFLAGS} -o $@ $< -module
