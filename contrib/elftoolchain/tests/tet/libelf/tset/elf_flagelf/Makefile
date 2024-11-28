# $Id: Makefile 4029 2024-01-15 16:16:49Z jkoshy $

TOP=	../../../../..

TS_SRCS=		elf.m4
TS_DATA=		a.ar

CLEANFILES=	zero

zero:
	touch ${.TARGET}

a.ar:	zero
	rm -f ${.TARGET}
	ar crv ${.TARGET} ${.ALLSRC}

.include "${TOP}/mk/elftoolchain.tet.mk"
