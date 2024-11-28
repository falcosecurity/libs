# Publish the Elftoolchain project's manual pages as static files on
# Sourceforge.
#
# $Id$

TOP=		../..

CSS=		mandoc.css

STAGING_DIRECTORY=	${.OBJDIR}/man

# The location of the manual page collection on SF's website.
SF_WEBDIR=	${USER}@web.sourceforge.net:/home/project-web/elftoolchain/htdocs/man

.MAIN:		all

all:		.PHONY
	${.CURDIR}/html-manpages.sh -t ${TOP} -c ${CSS} \
		-o ${STAGING_DIRECTORY}

publish:	all	.PHONY
	rsync -Jaz ${STAGING_DIRECTORY}/ ${SF_WEBDIR}/

clean:		.PHONY
	rm -rf ${STAGING_DIRECTORY}
