#
# Libelf by Example
#
# $Id: Makefile 3844 2020-03-19 20:43:16Z jkoshy $

TOP = ../..

DOC=			libelf-by-example

SRCS=			libelf-by-example.tex prog1.txt prog2.txt prog3.txt \
			prog4.txt prog5.txt prog6.txt
COVER_SRCS=		title-page-content.tex
GENERATED_VERSION_TEX=	version.tex

CLEANFILES+=		${SRCS:Mprog*:S/.txt/.c/}

.include "${TOP}/mk/elftoolchain.tex.mk"

.if ${OS_HOST} == "Linux"
EXTRA_FLAGS=	-I/usr/include/bsd -DLIBBSD_OVERLAY
EXTRA_LIBS=	-lbsd
.endif

check-example-syntax: .PHONY
.for f in ${SRCS:Mprog*:S/.txt//}
	@sed -e 's/@[^@]*@//' \
		${.CURDIR}/${f}.txt > ${.OBJDIR}/${f}.c; \
	echo -n ${f} ' '; \
	libelf="${.OBJDIR}/${TOP}/libelf";	\
	if [ ! -d $${libelf} -a "${.CURDIR}" != "${.OBJDIR}" ]; then	\
		suffix="${.OBJDIR:S,${.CURDIR}/,,}";	\
		libelf="${.CURDIR}/${TOP}/libelf/$${suffix}";	\
	fi; \
	cc -I${.CURDIR}/${TOP}/common \
		-I${.CURDIR}/${TOP}/libelf \
		${EXTRA_FLAGS} \
		${.OBJDIR}/${f}.c \
		-L"$${libelf}" -lelf ${EXTRA_LIBS} && \
		rm ${.OBJDIR}/a.out
.endfor
	@echo
