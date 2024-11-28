#
# $Id: elftoolchain.lib.mk 3913 2020-11-30 21:33:46Z jkoshy $
#

.if !defined(TOP)
.error	Make variable \"TOP\" has not been defined.
.endif

.include "${TOP}/mk/elftoolchain.os.mk"

.include <bsd.lib.mk>

# Support a 'clobber' target.
clobber:	clean os-specific-clobber .PHONY

# Remove '.depend' files on a "make clean".
CLEANFILES+=	.depend

# Determine the include directories to use.
_INCDIRS=	-I.			# OBJDIR
_INCDIRS+=	-I${.CURDIR}		# Sources
_INCDIRS+=	-I${.CURDIR}/${TOP}/common	# Common code
.if defined(MAKEOBJDIRPREFIX)
_INCDIRS+=	-I${.OBJDIR}/${TOP}/common	# Generated common code.
.else
.if ${.CURDIR} != ${.OBJDIR}
_INCDIRS+=	-I${.CURDIR}/${TOP}/common/${.OBJDIR:S/${.CURDIR}//}
.endif
.endif

.if defined(LDADD)
_LDADD_LIBELF=${LDADD:M-lelf}
.if !empty(_LDADD_LIBELF)
_INCDIRS+=	-I${.CURDIR}/${TOP}/libelf
LDFLAGS+=	-L${.OBJDIR}/${TOP}/libelf
.endif
.endif

# Set CFLAGS and LINTFLAGS.
CFLAGS+=	${_INCDIRS}
LINTFLAGS+=	${_INCDIRS}

# Note: include the M4 ruleset after bsd.lib.mk.
.include "${TOP}/mk/elftoolchain.m4.mk"

.if defined(DEBUG)
CFLAGS:=	${CFLAGS:N-O*} -g
.endif

.if ${OS_HOST} == "DragonFly" || ${OS_HOST} == "FreeBSD"
# Install headers too, in the 'install' phase.
install:	includes
.elif ${OS_HOST} == "Linux" || ${OS_HOST} == "NetBSD" || ${OS_HOST} == "Minix"
install:	incinstall
.elif ${OS_HOST} == "OpenBSD"

# OpenBSD's standard make ruleset does not install header files.  Provide
# an alternative.

NOBINMODE?=	444

install:	${INCS}	incinstall

.for inc in ${INCS}
incinstall::	${DESTDIR}${INCSDIR}/${inc}
.PRECIOUS:	${DESTDIR}${INCSDIR}/${inc}
${DESTDIR}${INCSDIR}/${inc}: ${inc}
	cmp -s $> $@ > /dev/null 2>&1 || \
		${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m ${NOBINMODE} $> $@
.endfor

.endif	# OpenBSD

# Bring in rules related to running the related test suite.
.include "${TOP}/mk/elftoolchain.test-target.mk"
