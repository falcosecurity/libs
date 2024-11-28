# $Id: Makefile 4029 2024-01-15 16:16:49Z jkoshy $

TOP=		../../..
AR=		${TOP}/ar/ar

TEST_LOG=	test.log

.MAIN:	all

.PHONY:	clobber execute test

execute test: ${AR}
	/bin/sh run.sh

clean clobber:
	rm -f ${TEST_LOG}

SUBDIR=		plugin

.include "${TOP}/mk/elftoolchain.subdir.mk"
