# $Id: Makefile 4029 2024-01-15 16:16:49Z jkoshy $

TOP=	../../../../..

TS_SRCS=		cntl.m4
TS_DATA=		a.ar
CLEANFILES+=		a.c a.o

a.c:	.SILENT
	echo "int foobar;" > ${.TARGET}

a.ar:	a.o .SILENT
	rm -f ${.TARGET}
	${AR} crv ${.TARGET} ${.ALLSRC} > /dev/null

.include "${TOP}/mk/elftoolchain.tet.mk"
