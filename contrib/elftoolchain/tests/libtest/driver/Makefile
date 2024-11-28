# $Id$
#
# A command-line driver for libtest based tests.

TOP=	../../..

INCDIR=		-I${TOP}/tests/libtest/lib
CFLAGS+=	${INCDIR}
LINTFLAGS+=	${INCDIR}

LIB=	driver
SRCS=	driver.c \
	driver_main.c

WARNS?=	6

MAN=	test_driver.1

.include "$(TOP)/mk/elftoolchain.lib.mk"
