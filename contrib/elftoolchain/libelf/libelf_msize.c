/*-
 * Copyright (c) 2006,2008-2011 Joseph Koshy
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS `AS IS' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*@ELFTC-INCLUDE-SYS-CDEFS@*/

#include <assert.h>
#include <libelf.h>
#include <string.h>

#include "_libelf.h"

ELFTC_VCSID("$Id: libelf_msize.m4 3977 2022-05-01 06:45:34Z jkoshy $");

/*@ELFTC-USE-DOWNSTREAM-VCSID@*/

/* WARNING: GENERATED FROM libelf_msize.m4. */

struct msize {
	size_t	msz32;
	size_t	msz64;
};



static struct msize msize[ELF_T_NUM] = {
[ELF_T_ADDR] = { .msz32 = sizeof(Elf32_Addr), .msz64 = sizeof(Elf64_Addr) },

[ELF_T_BYTE] = { .msz32 = 1, .msz64 = 1 },

[ELF_T_CAP] = { .msz32 = sizeof(Elf32_Cap), .msz64 = sizeof(Elf64_Cap) },

[ELF_T_DYN] = { .msz32 = sizeof(Elf32_Dyn), .msz64 = sizeof(Elf64_Dyn) },

[ELF_T_EHDR] = { .msz32 = sizeof(Elf32_Ehdr), .msz64 = sizeof(Elf64_Ehdr) },

[ELF_T_GNUHASH] = { .msz32 = 1, .msz64 = 1 },

[ELF_T_HALF] = { .msz32 = sizeof(Elf32_Half), .msz64 = sizeof(Elf64_Half) },

[ELF_T_LWORD] = { .msz32 = sizeof(Elf32_Lword), .msz64 = sizeof(Elf64_Lword) },

[ELF_T_MOVE] = { .msz32 = sizeof(Elf32_Move), .msz64 = sizeof(Elf64_Move) },

[ELF_T_MOVEP] = { .msz32 = 0, .msz64 = 0 },

[ELF_T_NOTE] = { .msz32 = 1, .msz64 = 1 },

[ELF_T_OFF] = { .msz32 = sizeof(Elf32_Off), .msz64 = sizeof(Elf64_Off) },

[ELF_T_PHDR] = { .msz32 = sizeof(Elf32_Phdr), .msz64 = sizeof(Elf64_Phdr) },

[ELF_T_REL] = { .msz32 = sizeof(Elf32_Rel), .msz64 = sizeof(Elf64_Rel) },

[ELF_T_RELA] = { .msz32 = sizeof(Elf32_Rela), .msz64 = sizeof(Elf64_Rela) },

[ELF_T_SHDR] = { .msz32 = sizeof(Elf32_Shdr), .msz64 = sizeof(Elf64_Shdr) },

[ELF_T_SWORD] = { .msz32 = sizeof(Elf32_Sword), .msz64 = sizeof(Elf64_Sword) },

[ELF_T_SXWORD] = { .msz32 = 0, .msz64 = sizeof(Elf64_Sxword) },

[ELF_T_SYMINFO] = { .msz32 = sizeof(Elf32_Syminfo), .msz64 = sizeof(Elf64_Syminfo) },

[ELF_T_SYM] = { .msz32 = sizeof(Elf32_Sym), .msz64 = sizeof(Elf64_Sym) },

[ELF_T_VDEF] = { .msz32 = 1, .msz64 = 1 },

[ELF_T_VNEED] = { .msz32 = 1, .msz64 = 1 },

[ELF_T_WORD] = { .msz32 = sizeof(Elf32_Word), .msz64 = sizeof(Elf64_Word) },

[ELF_T_XWORD] = { .msz32 = 0, .msz64 = sizeof(Elf64_Xword) },


};

/*
 * Returns the memory size of the specified ELF type 't' of ELF
 * class 'ec' and ELF version 'version'.
 *
 * If the specified combination of ELF type, class, and version is
 * unsupported then a value of 0 will be returned and the appropriate
 * library error code set.
 */
size_t
_libelf_msize(Elf_Type t, int elfclass, unsigned int version)
{
	size_t sz;

	assert(elfclass == ELFCLASS32 || elfclass == ELFCLASS64);
	assert((signed) t >= ELF_T_FIRST && t <= ELF_T_LAST);

	if (version != EV_CURRENT) {
		LIBELF_SET_ERROR(VERSION, 0);
		return (0);
	}

	sz = (elfclass == ELFCLASS32) ? msize[t].msz32 : msize[t].msz64;

	if (sz == 0) {
		LIBELF_SET_ERROR(UNIMPL, 0);
		return (0);
	}

	return (sz);
}
