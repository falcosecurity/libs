/*-
 * Copyright (c) 2021 Joseph Koshy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#include <libelf.h>
#include <unistd.h>

#include "elfts.h"
#include "tet_api.h"

include(`elfts.m4')

IC_REQUIRES_VERSION_INIT();

/*
 * elf_getversion() fails with a NULL argument.
 */
void
tcArgsNull(void)
{
	int error, result;
	unsigned int version;

	error = 0;
	result = TET_UNRESOLVED;
	version = EV_CURRENT;

	TP_CHECK_INITIALIZATION();

	TP_ANNOUNCE("elf_getversion(NULL) fails.");

	if ((version = elf_getversion(NULL)) != EV_NONE)
		TP_FAIL("version=%d", version);
	else if ((error = elf_errno()) != ELF_E_ARGUMENT)
	        TP_FAIL("error=%d \"%s\".", error, elf_errmsg(error));
	else
		result = TET_PASS;

	tet_result(result);
}

/*
 * elf_getversion() on a non-ELF object fails.
 */
static char *nonelf = "This is not an ELF object.";

void
tcArgsNonElf(void)
{
	Elf *e;
	int error, result;
	unsigned int version;

	e = NULL;
	error = 0;
	version = EV_CURRENT;
	result = TET_UNRESOLVED;

	TP_CHECK_INITIALIZATION();

	TP_ANNOUNCE("elf_getversion(non-elf) fails.");

	TS_OPEN_MEMORY(e, nonelf);

	if ((version = elf_getversion(e)) != EV_NONE)
		TP_FAIL("version=%d", version);
	else if ((error = elf_errno()) != ELF_E_ARGUMENT)
	        TP_FAIL("error=%d \"%s\".", error, elf_errmsg(error));
	else
		result = TET_PASS;

	(void) elf_end(e);

	tet_result(result);
}

/*
 * elf_version() fails on ar(1) archives.
 */
void
tcArgsArArchive(void)
{
	Elf *e;
	int error, fd, result;
	unsigned int version;

	e = NULL;
	error = 0;
	fd = -1;
	result = TET_UNRESOLVED;
	version = EV_CURRENT;

	TP_CHECK_INITIALIZATION();

	TP_ANNOUNCE("elf_getversion(ar-archive) fails.");

	_TS_OPEN_FILE(e, "a.ar", ELF_C_READ, fd, goto done;);

	if ((version = elf_getversion(e)) != EV_NONE)
		TP_FAIL("version=%d expected EV_NONE", version);
	else if ((error = elf_errno()) != ELF_E_ARGUMENT)
		TP_FAIL("error=%d \"%s\"", error, elf_errmsg(error));
	else
		result = TET_PASS;

 done:
	if (e)
		(void) elf_end(e);
	if (fd != -1)
		(void) close(fd);

	tet_result(result);
}

/*
 * elf_getversion() succeeds on well-formed ELF files.
 */
undefine(`FN')
define(`FN',`
void
tcNormal$1_$2(void)
{
	Elf *e;
	int fd, result;
	unsigned int version;

	fd = -1;
	e = NULL;
	result = TET_UNRESOLVED;
	version = EV_NONE;

	TP_CHECK_INITIALIZATION();

	TP_ANNOUNCE("elf_getversion($2$1) succeeds.");

	_TS_OPEN_FILE(e, "check_elf.$2$1", ELF_C_READ, fd, goto done;);

	if ((version = elf_getversion(e)) != EV_CURRENT)
		TP_FAIL("version=%d", version);
	else
		result = TET_PASS;

 done:
	if (e)
		(void) elf_end(e);
	if (fd != -1)
		(void) close(fd);

	tet_result(result);
}')

FN(32,`lsb')
FN(32,`msb')
FN(64,`lsb')
FN(64,`msb')
