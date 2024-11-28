#
# Rules for recursing into directories
# $Id: elftoolchain.subdir.mk 4033 2024-01-16 16:29:17Z jkoshy $

# Pass down 'test' as a valid target.

.include "$(TOP)/mk/elftoolchain.os.mk"

.if ${OS_HOST} == FreeBSD
SUBDIR_TARGETS+=	clobber test
.elif ${OS_HOST} == OpenBSD
clobber: _SUBDIRUSE
.elif ${OS_HOST} == Linux  # Ubuntu 'bmake' version 20200710-15.
SUBDIR_TARGETS+=	cleandepend clobber test
.else		# NetBSD
TARGETS+=	cleandepend clobber test
.endif

.include <bsd.subdir.mk>
