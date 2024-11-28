# $Id: os.FreeBSD.mk 4004 2023-04-16 18:12:54Z jkoshy $
#
# Build definitions for FreeBSD

MKDOC?=		yes	# Build documentation.
MKTESTS?=	yes	# Enable the test suites.
MKTEX?=		yes	# TeX and friends are packaged in the teTeX package.
MKNOWEB?=	no	# Build literate programs.

# Link programs statically by default.
NO_SHARED?=	yes

.if defined(MKTEX) && ${MKTEX} == "yes"
EPSTOPDF?=	/usr/local/bin/epstopdf
MAKEINDEX?=	/usr/local/bin/makeindex
MPOSTTEX?=	/usr/local/bin/latex
MPOST?=		/usr/local/bin/mpost
PDFJAM?=	/usr/local/bin/pdfjam
PDFLATEX?=	/usr/local/bin/pdflatex
.endif

# Translate the spelling of a build knob (see ticket #316).
.if defined(NOMAN)
MK_MAN=		no	# FreeBSD 7 and later.
.endif

# Literate programming utility.
NOWEB?=		/usr/local/bin/noweb
PYTHON?=	/usr/local/bin/python3.9
