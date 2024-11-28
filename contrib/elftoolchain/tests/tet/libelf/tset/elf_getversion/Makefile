# $Id$

TOP=	../../../../..

TS_SRCS=	getversion.m4
TS_DATA=	check_elf.msb32 check_elf.lsb32 check_elf.msb64 \
		check_elf.lsb64 a.ar s1

s1:	.SILENT
	echo 'This is s1.' > ${.TARGET}

a.ar:	s1 .SILENT
	rm -f ${.TARGET}
	${AR} crv ${.TARGET} s1 > /dev/null

.include "${TOP}/mk/elftoolchain.tet.mk"
