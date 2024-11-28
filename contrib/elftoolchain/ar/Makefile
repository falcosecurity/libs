# $Id: Makefile 4045 2024-07-08 12:36:29Z jkoshy $

TOP=	..

PROG=	ar
SRCS=	ar.c read.c util.c write.c
LSRC=	acplex.l
YSRC=	acpyacc.y

WARNS?=	5

DPADD=	${LIBARCHIVE} ${LIBELFTC} ${LIBELF} ${LIBZ}
LDADD=	-larchive -lelftc -lelf -lz

CFLAGS+=-I. -I${.CURDIR}

LINKS=	${BINDIR}/ar ${BINDIR}/ranlib

EXTRA_TARGETS=	ranlib

CLEANFILES+= 	${EXTRA_TARGETS}

MAN=	ar.1 ranlib.1 ar.5

TEST_FRAMEWORK=	custom

all:	${EXTRA_TARGETS}

${EXTRA_TARGETS}:	${PROG}
	ln -s ${PROG} ${.TARGET}

.include "${TOP}/mk/elftoolchain.prog.mk"

.if ${OS_HOST} == "OpenBSD"
CFLAGS+=	-I/usr/local/include
LDFLAGS+=	-L/usr/local/lib
.elif ${OS_HOST} == "DragonFly"
LDADD+=	-lbz2
.endif
