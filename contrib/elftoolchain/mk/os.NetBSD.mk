# $Id: os.NetBSD.mk 3888 2020-11-11 19:26:14Z jkoshy $
#
# Build recipes for NetBSD.

LDSTATIC?=	-static		# link programs statically

MKDOC?=		yes		# Build documentation.
MKLINT?=	no		# lint dies with a sigbus
MKTESTS?=	yes		# Enable the test suites.
MKNOWEB?=	no		# Build literate programs.
PYTHON?=	/usr/pkg/bin/python3.8

# Literate programming utility.
NOWEB?=		/usr/pkgsrc/bin/noweb

# NetBSD's 'clean' target does not remove 'cat[0-9]' and 'html[0-9]'
# files generate from manual page sources.  Augment the 'clobber'
# target to remove these.
os-specific-clobber: .PHONY
.for f in cat html
	rm -f ${MANPAGES:@M@${M:R}.$f${M:E}@}
.endfor
