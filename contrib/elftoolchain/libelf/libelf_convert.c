/*-
 * Copyright (c) 2006-2011 Joseph Koshy
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

ELFTC_VCSID("$Id: libelf_convert.m4 3977 2022-05-01 06:45:34Z jkoshy $");

/*@ELFTC-USE-DOWNSTREAM-VCSID@*/

/* WARNING: GENERATED FROM libelf_convert.m4. */



/*
 * C macros to byte swap integral quantities.
 */

#define	SWAP_BYTE(X)	do { (void) (X); } while (/*CONSTCOND*/0)
#define	SWAP_IDENT(X)	do { (void) (X); } while (/*CONSTCOND*/0)
#define	SWAP_HALF(X)	do {						\
		uint16_t _x = (uint16_t) (X);				\
		uint32_t _t = _x & 0xFFU;				\
		_t <<= 8U; _x >>= 8U; _t |= _x & 0xFFU;			\
		(X) = (uint16_t) _t;					\
	} while (/*CONSTCOND*/0)
#define	_SWAP_WORD(X, T) do {						\
		uint32_t _x = (uint32_t) (X);				\
		uint32_t _t = _x & 0xFF;				\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		(X) = (T) _t;						\
	} while (/*CONSTCOND*/0)
#define	SWAP_ADDR32(X)	_SWAP_WORD(X, Elf32_Addr)
#define	SWAP_OFF32(X)	_SWAP_WORD(X, Elf32_Off)
#define	SWAP_SWORD(X)	_SWAP_WORD(X, Elf32_Sword)
#define	SWAP_WORD(X)	_SWAP_WORD(X, Elf32_Word)
#define	_SWAP_WORD64(X, T) do {						\
		uint64_t _x = (uint64_t) (X);				\
		uint64_t _t = _x & 0xFF;				\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		_t <<= 8; _x >>= 8; _t |= _x & 0xFF;			\
		(X) = (T) _t;						\
	} while (/*CONSTCOND*/0)
#define	SWAP_ADDR64(X)	_SWAP_WORD64(X, Elf64_Addr)
#define	SWAP_LWORD(X)	_SWAP_WORD64(X, Elf64_Lword)
#define	SWAP_OFF64(X)	_SWAP_WORD64(X, Elf64_Off)
#define	SWAP_SXWORD(X)	_SWAP_WORD64(X, Elf64_Sxword)
#define	SWAP_XWORD(X)	_SWAP_WORD64(X, Elf64_Xword)

/*
 * C macros to write out various integral values.
 *
 * Note:
 * - The destination pointer could be unaligned.
 * - Values are written out in native byte order.
 * - The destination pointer is incremented after the write.
 */
#define	WRITE_BYTE(P,X) do {						\
		unsigned char *const _p = (unsigned char *) (P);	\
		_p[0]		= (unsigned char) (X);			\
		(P)		= _p + 1;				\
	} while (/*CONSTCOND*/0)
#define	WRITE_HALF(P,X)	do {						\
		uint16_t _t	= (X);					\
		unsigned char *const _p	= (unsigned char *) (P);	\
		const unsigned char *const _q = (unsigned char *) &_t;	\
		_p[0]		= _q[0];				\
		_p[1]		= _q[1];				\
		(P)		= _p + 2;				\
	} while (/*CONSTCOND*/0)
#define	WRITE_WORD(P,X) do {						\
		uint32_t _t	= (uint32_t) (X);			\
		unsigned char *const _p	= (unsigned char *) (P);	\
		const unsigned char *const _q = (unsigned char *) &_t;	\
		_p[0]		= _q[0];				\
		_p[1]		= _q[1];				\
		_p[2]		= _q[2];				\
		_p[3]		= _q[3];				\
		(P)		= _p + 4;				\
	} while (/*CONSTCOND*/0)
#define	WRITE_ADDR32(P,X)	WRITE_WORD(P,X)
#define	WRITE_OFF32(P,X)	WRITE_WORD(P,X)
#define	WRITE_SWORD(P,X)	WRITE_WORD(P,X)
#define	WRITE_WORD64(P,X)	do {					\
		uint64_t _t	= (uint64_t) (X);			\
		unsigned char *const _p	= (unsigned char *) (P);	\
		const unsigned char *const _q = (unsigned char *) &_t;	\
		_p[0]		= _q[0];				\
		_p[1]		= _q[1];				\
		_p[2]		= _q[2];				\
		_p[3]		= _q[3];				\
		_p[4]		= _q[4];				\
		_p[5]		= _q[5];				\
		_p[6]		= _q[6];				\
		_p[7]		= _q[7];				\
		(P)		= _p + 8;				\
	} while (/*CONSTCOND*/0)
#define	WRITE_ADDR64(P,X)	WRITE_WORD64(P,X)
#define	WRITE_LWORD(P,X)	WRITE_WORD64(P,X)
#define	WRITE_OFF64(P,X)	WRITE_WORD64(P,X)
#define	WRITE_SXWORD(P,X)	WRITE_WORD64(P,X)
#define	WRITE_XWORD(P,X)	WRITE_WORD64(P,X)
#define	WRITE_IDENT(P,X)	do {					\
		(void) memcpy((P), (X), sizeof((X)));			\
		(P)		= (P) + EI_NIDENT;			\
	} while (/*CONSTCOND*/0)

/*
 * C macros to read in various integral values.
 *
 * Note:
 * - The source pointer could be unaligned.
 * - Values are read in native byte order.
 * - The source pointer is incremented appropriately.
 */

#define	READ_BYTE(P,X)	do {						\
		const unsigned char *const _p =				\
			(const unsigned char *) (P);			\
		(X)		= _p[0];				\
		(P)		= (P) + 1;				\
	} while (/*CONSTCOND*/0)
#define	READ_HALF(P,X)	do {						\
		uint16_t _t;						\
		unsigned char *const _q = (unsigned char *) &_t;	\
		const unsigned char *const _p =				\
			(const unsigned char *) (P);			\
		_q[0]		= _p[0];				\
		_q[1]		= _p[1];				\
		(P)		= (P) + 2;				\
		(X)		= _t;					\
	} while (/*CONSTCOND*/0)
#define	_READ_WORD(P,X,T) do {						\
		uint32_t _t;						\
		unsigned char *const _q = (unsigned char *) &_t;	\
		const unsigned char *const _p =				\
			(const unsigned char *) (P);			\
		_q[0]		= _p[0];				\
		_q[1]		= _p[1];				\
		_q[2]		= _p[2];				\
		_q[3]		= _p[3];				\
		(P)		= (P) + 4;				\
		(X)		= (T) _t;				\
	} while (/*CONSTCOND*/0)
#define	READ_ADDR32(P,X)	_READ_WORD(P, X, Elf32_Addr)
#define	READ_OFF32(P,X)		_READ_WORD(P, X, Elf32_Off)
#define	READ_SWORD(P,X)		_READ_WORD(P, X, Elf32_Sword)
#define	READ_WORD(P,X)		_READ_WORD(P, X, Elf32_Word)
#define	_READ_WORD64(P,X,T)	do {					\
		uint64_t _t;						\
		unsigned char *const _q = (unsigned char *) &_t;	\
		const unsigned char *const _p =				\
			(const unsigned char *) (P);			\
		_q[0]		= _p[0];				\
		_q[1]		= _p[1];				\
		_q[2]		= _p[2];				\
		_q[3]		= _p[3];				\
		_q[4]		= _p[4];				\
		_q[5]		= _p[5];				\
		_q[6]		= _p[6];				\
		_q[7]		= _p[7];				\
		(P)		= (P) + 8;				\
		(X)		= (T) _t;				\
	} while (/*CONSTCOND*/0)
#define	READ_ADDR64(P,X)	_READ_WORD64(P, X, Elf64_Addr)
#define	READ_LWORD(P,X)		_READ_WORD64(P, X, Elf64_Lword)
#define	READ_OFF64(P,X)		_READ_WORD64(P, X, Elf64_Off)
#define	READ_SXWORD(P,X)	_READ_WORD64(P, X, Elf64_Sxword)
#define	READ_XWORD(P,X)		_READ_WORD64(P, X, Elf64_Xword)
#define	READ_IDENT(P,X)		do {					\
		(void) memcpy((X), (P), sizeof((X)));			\
		(P)		= (P) + EI_NIDENT;			\
	} while (/*CONSTCOND*/0)

#define	ROUNDUP2(V,N)	(V) = ((((V) + (N) - 1)) & ~((N) - 1))

/*[*/

static int
_libelf_cvt_ADDR32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Addr t, *s = (Elf32_Addr *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_ADDR32(t);
		WRITE_ADDR32(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_ADDR32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Addr t, *d = (Elf32_Addr *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf32_Addr))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_ADDR32(src,t);
		SWAP_ADDR32(t);
		*d++ = t;
	}

	return (1);
}
	 
static int
_libelf_cvt_ADDR64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Addr t, *s = (Elf64_Addr *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_ADDR64(t);
		WRITE_ADDR64(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_ADDR64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Addr t, *d = (Elf64_Addr *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Addr))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_ADDR64(src,t);
		SWAP_ADDR64(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_CAP32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Cap	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Cap *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Cap */
			SWAP_WORD(t.c_tag);
			SWAP_WORD(t.c_un.c_val);
			/**/
		}
		/* Write an Elf32_Cap */
		WRITE_WORD(dst,t.c_tag);
		WRITE_WORD(dst,t.c_un.c_val);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_CAP32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Cap	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_CAP, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Cap *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Cap))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Cap */
		READ_WORD(s,t.c_tag);
		READ_WORD(s,t.c_un.c_val);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Cap */
			SWAP_WORD(t.c_tag);
			SWAP_WORD(t.c_un.c_val);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_CAP64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Cap	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Cap *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Cap */
			SWAP_XWORD(t.c_tag);
			SWAP_XWORD(t.c_un.c_val);
			/**/
		}
		/* Write an Elf64_Cap */
		WRITE_XWORD(dst,t.c_tag);
		WRITE_XWORD(dst,t.c_un.c_val);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_CAP64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Cap	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_CAP, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Cap *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Cap))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Cap */
		READ_XWORD(s,t.c_tag);
		READ_XWORD(s,t.c_un.c_val);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Cap */
			SWAP_XWORD(t.c_tag);
			SWAP_XWORD(t.c_un.c_val);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_DYN32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Dyn	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Dyn *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Dyn */
			SWAP_SWORD(t.d_tag);
			SWAP_WORD(t.d_un.d_ptr);
			/**/
		}
		/* Write an Elf32_Dyn */
		WRITE_SWORD(dst,t.d_tag);
		WRITE_WORD(dst,t.d_un.d_ptr);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_DYN32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Dyn	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_DYN, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Dyn *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Dyn))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Dyn */
		READ_SWORD(s,t.d_tag);
		READ_WORD(s,t.d_un.d_ptr);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Dyn */
			SWAP_SWORD(t.d_tag);
			SWAP_WORD(t.d_un.d_ptr);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_DYN64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Dyn	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Dyn *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Dyn */
			SWAP_SXWORD(t.d_tag);
			SWAP_XWORD(t.d_un.d_ptr);
			/**/
		}
		/* Write an Elf64_Dyn */
		WRITE_SXWORD(dst,t.d_tag);
		WRITE_XWORD(dst,t.d_un.d_ptr);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_DYN64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Dyn	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_DYN, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Dyn *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Dyn))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Dyn */
		READ_SXWORD(s,t.d_tag);
		READ_XWORD(s,t.d_un.d_ptr);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Dyn */
			SWAP_SXWORD(t.d_tag);
			SWAP_XWORD(t.d_un.d_ptr);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_EHDR32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Ehdr	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Ehdr *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Ehdr */
			SWAP_IDENT(t.e_ident);
			SWAP_HALF(t.e_type);
			SWAP_HALF(t.e_machine);
			SWAP_WORD(t.e_version);
			SWAP_ADDR32(t.e_entry);
			SWAP_OFF32(t.e_phoff);
			SWAP_OFF32(t.e_shoff);
			SWAP_WORD(t.e_flags);
			SWAP_HALF(t.e_ehsize);
			SWAP_HALF(t.e_phentsize);
			SWAP_HALF(t.e_phnum);
			SWAP_HALF(t.e_shentsize);
			SWAP_HALF(t.e_shnum);
			SWAP_HALF(t.e_shstrndx);
			/**/
		}
		/* Write an Elf32_Ehdr */
		WRITE_IDENT(dst,t.e_ident);
		WRITE_HALF(dst,t.e_type);
		WRITE_HALF(dst,t.e_machine);
		WRITE_WORD(dst,t.e_version);
		WRITE_ADDR32(dst,t.e_entry);
		WRITE_OFF32(dst,t.e_phoff);
		WRITE_OFF32(dst,t.e_shoff);
		WRITE_WORD(dst,t.e_flags);
		WRITE_HALF(dst,t.e_ehsize);
		WRITE_HALF(dst,t.e_phentsize);
		WRITE_HALF(dst,t.e_phnum);
		WRITE_HALF(dst,t.e_shentsize);
		WRITE_HALF(dst,t.e_shnum);
		WRITE_HALF(dst,t.e_shstrndx);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_EHDR32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Ehdr	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_EHDR, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Ehdr *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Ehdr))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Ehdr */
		READ_IDENT(s,t.e_ident);
		READ_HALF(s,t.e_type);
		READ_HALF(s,t.e_machine);
		READ_WORD(s,t.e_version);
		READ_ADDR32(s,t.e_entry);
		READ_OFF32(s,t.e_phoff);
		READ_OFF32(s,t.e_shoff);
		READ_WORD(s,t.e_flags);
		READ_HALF(s,t.e_ehsize);
		READ_HALF(s,t.e_phentsize);
		READ_HALF(s,t.e_phnum);
		READ_HALF(s,t.e_shentsize);
		READ_HALF(s,t.e_shnum);
		READ_HALF(s,t.e_shstrndx);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Ehdr */
			SWAP_IDENT(t.e_ident);
			SWAP_HALF(t.e_type);
			SWAP_HALF(t.e_machine);
			SWAP_WORD(t.e_version);
			SWAP_ADDR32(t.e_entry);
			SWAP_OFF32(t.e_phoff);
			SWAP_OFF32(t.e_shoff);
			SWAP_WORD(t.e_flags);
			SWAP_HALF(t.e_ehsize);
			SWAP_HALF(t.e_phentsize);
			SWAP_HALF(t.e_phnum);
			SWAP_HALF(t.e_shentsize);
			SWAP_HALF(t.e_shnum);
			SWAP_HALF(t.e_shstrndx);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_EHDR64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Ehdr	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Ehdr *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Ehdr */
			SWAP_IDENT(t.e_ident);
			SWAP_HALF(t.e_type);
			SWAP_HALF(t.e_machine);
			SWAP_WORD(t.e_version);
			SWAP_ADDR64(t.e_entry);
			SWAP_OFF64(t.e_phoff);
			SWAP_OFF64(t.e_shoff);
			SWAP_WORD(t.e_flags);
			SWAP_HALF(t.e_ehsize);
			SWAP_HALF(t.e_phentsize);
			SWAP_HALF(t.e_phnum);
			SWAP_HALF(t.e_shentsize);
			SWAP_HALF(t.e_shnum);
			SWAP_HALF(t.e_shstrndx);
			/**/
		}
		/* Write an Elf64_Ehdr */
		WRITE_IDENT(dst,t.e_ident);
		WRITE_HALF(dst,t.e_type);
		WRITE_HALF(dst,t.e_machine);
		WRITE_WORD(dst,t.e_version);
		WRITE_ADDR64(dst,t.e_entry);
		WRITE_OFF64(dst,t.e_phoff);
		WRITE_OFF64(dst,t.e_shoff);
		WRITE_WORD(dst,t.e_flags);
		WRITE_HALF(dst,t.e_ehsize);
		WRITE_HALF(dst,t.e_phentsize);
		WRITE_HALF(dst,t.e_phnum);
		WRITE_HALF(dst,t.e_shentsize);
		WRITE_HALF(dst,t.e_shnum);
		WRITE_HALF(dst,t.e_shstrndx);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_EHDR64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Ehdr	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_EHDR, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Ehdr *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Ehdr))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Ehdr */
		READ_IDENT(s,t.e_ident);
		READ_HALF(s,t.e_type);
		READ_HALF(s,t.e_machine);
		READ_WORD(s,t.e_version);
		READ_ADDR64(s,t.e_entry);
		READ_OFF64(s,t.e_phoff);
		READ_OFF64(s,t.e_shoff);
		READ_WORD(s,t.e_flags);
		READ_HALF(s,t.e_ehsize);
		READ_HALF(s,t.e_phentsize);
		READ_HALF(s,t.e_phnum);
		READ_HALF(s,t.e_shentsize);
		READ_HALF(s,t.e_shnum);
		READ_HALF(s,t.e_shstrndx);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Ehdr */
			SWAP_IDENT(t.e_ident);
			SWAP_HALF(t.e_type);
			SWAP_HALF(t.e_machine);
			SWAP_WORD(t.e_version);
			SWAP_ADDR64(t.e_entry);
			SWAP_OFF64(t.e_phoff);
			SWAP_OFF64(t.e_shoff);
			SWAP_WORD(t.e_flags);
			SWAP_HALF(t.e_ehsize);
			SWAP_HALF(t.e_phentsize);
			SWAP_HALF(t.e_phnum);
			SWAP_HALF(t.e_shentsize);
			SWAP_HALF(t.e_shnum);
			SWAP_HALF(t.e_shstrndx);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_HALF_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Half t, *s = (Elf64_Half *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_HALF(t);
		WRITE_HALF(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_HALF_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Half t, *d = (Elf64_Half *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Half))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_HALF(src,t);
		SWAP_HALF(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_LWORD_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Lword t, *s = (Elf64_Lword *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_LWORD(t);
		WRITE_LWORD(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_LWORD_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Lword t, *d = (Elf64_Lword *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Lword))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_LWORD(src,t);
		SWAP_LWORD(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_MOVE32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Move	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Move *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Move */
			SWAP_LWORD(t.m_value);
			SWAP_WORD(t.m_info);
			SWAP_WORD(t.m_poffset);
			SWAP_HALF(t.m_repeat);
			SWAP_HALF(t.m_stride);
			/**/
		}
		/* Write an Elf32_Move */
		WRITE_LWORD(dst,t.m_value);
		WRITE_WORD(dst,t.m_info);
		WRITE_WORD(dst,t.m_poffset);
		WRITE_HALF(dst,t.m_repeat);
		WRITE_HALF(dst,t.m_stride);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_MOVE32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Move	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_MOVE, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Move *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Move))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Move */
		READ_LWORD(s,t.m_value);
		READ_WORD(s,t.m_info);
		READ_WORD(s,t.m_poffset);
		READ_HALF(s,t.m_repeat);
		READ_HALF(s,t.m_stride);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Move */
			SWAP_LWORD(t.m_value);
			SWAP_WORD(t.m_info);
			SWAP_WORD(t.m_poffset);
			SWAP_HALF(t.m_repeat);
			SWAP_HALF(t.m_stride);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_MOVE64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Move	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Move *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Move */
			SWAP_LWORD(t.m_value);
			SWAP_XWORD(t.m_info);
			SWAP_XWORD(t.m_poffset);
			SWAP_HALF(t.m_repeat);
			SWAP_HALF(t.m_stride);
			/**/
		}
		/* Write an Elf64_Move */
		WRITE_LWORD(dst,t.m_value);
		WRITE_XWORD(dst,t.m_info);
		WRITE_XWORD(dst,t.m_poffset);
		WRITE_HALF(dst,t.m_repeat);
		WRITE_HALF(dst,t.m_stride);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_MOVE64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Move	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_MOVE, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Move *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Move))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Move */
		READ_LWORD(s,t.m_value);
		READ_XWORD(s,t.m_info);
		READ_XWORD(s,t.m_poffset);
		READ_HALF(s,t.m_repeat);
		READ_HALF(s,t.m_stride);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Move */
			SWAP_LWORD(t.m_value);
			SWAP_XWORD(t.m_info);
			SWAP_XWORD(t.m_poffset);
			SWAP_HALF(t.m_repeat);
			SWAP_HALF(t.m_stride);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_OFF32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Off t, *s = (Elf32_Off *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_OFF32(t);
		WRITE_OFF32(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_OFF32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Off t, *d = (Elf32_Off *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf32_Off))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_OFF32(src,t);
		SWAP_OFF32(t);
		*d++ = t;
	}

	return (1);
}
	 
static int
_libelf_cvt_OFF64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Off t, *s = (Elf64_Off *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_OFF64(t);
		WRITE_OFF64(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_OFF64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Off t, *d = (Elf64_Off *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Off))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_OFF64(src,t);
		SWAP_OFF64(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_PHDR32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Phdr	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Phdr *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Phdr */
			SWAP_WORD(t.p_type);
			SWAP_OFF32(t.p_offset);
			SWAP_ADDR32(t.p_vaddr);
			SWAP_ADDR32(t.p_paddr);
			SWAP_WORD(t.p_filesz);
			SWAP_WORD(t.p_memsz);
			SWAP_WORD(t.p_flags);
			SWAP_WORD(t.p_align);
			/**/
		}
		/* Write an Elf32_Phdr */
		WRITE_WORD(dst,t.p_type);
		WRITE_OFF32(dst,t.p_offset);
		WRITE_ADDR32(dst,t.p_vaddr);
		WRITE_ADDR32(dst,t.p_paddr);
		WRITE_WORD(dst,t.p_filesz);
		WRITE_WORD(dst,t.p_memsz);
		WRITE_WORD(dst,t.p_flags);
		WRITE_WORD(dst,t.p_align);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_PHDR32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Phdr	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_PHDR, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Phdr *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Phdr))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Phdr */
		READ_WORD(s,t.p_type);
		READ_OFF32(s,t.p_offset);
		READ_ADDR32(s,t.p_vaddr);
		READ_ADDR32(s,t.p_paddr);
		READ_WORD(s,t.p_filesz);
		READ_WORD(s,t.p_memsz);
		READ_WORD(s,t.p_flags);
		READ_WORD(s,t.p_align);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Phdr */
			SWAP_WORD(t.p_type);
			SWAP_OFF32(t.p_offset);
			SWAP_ADDR32(t.p_vaddr);
			SWAP_ADDR32(t.p_paddr);
			SWAP_WORD(t.p_filesz);
			SWAP_WORD(t.p_memsz);
			SWAP_WORD(t.p_flags);
			SWAP_WORD(t.p_align);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_PHDR64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Phdr	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Phdr *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Phdr */
			SWAP_WORD(t.p_type);
			SWAP_WORD(t.p_flags);
			SWAP_OFF64(t.p_offset);
			SWAP_ADDR64(t.p_vaddr);
			SWAP_ADDR64(t.p_paddr);
			SWAP_XWORD(t.p_filesz);
			SWAP_XWORD(t.p_memsz);
			SWAP_XWORD(t.p_align);
			/**/
		}
		/* Write an Elf64_Phdr */
		WRITE_WORD(dst,t.p_type);
		WRITE_WORD(dst,t.p_flags);
		WRITE_OFF64(dst,t.p_offset);
		WRITE_ADDR64(dst,t.p_vaddr);
		WRITE_ADDR64(dst,t.p_paddr);
		WRITE_XWORD(dst,t.p_filesz);
		WRITE_XWORD(dst,t.p_memsz);
		WRITE_XWORD(dst,t.p_align);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_PHDR64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Phdr	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_PHDR, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Phdr *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Phdr))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Phdr */
		READ_WORD(s,t.p_type);
		READ_WORD(s,t.p_flags);
		READ_OFF64(s,t.p_offset);
		READ_ADDR64(s,t.p_vaddr);
		READ_ADDR64(s,t.p_paddr);
		READ_XWORD(s,t.p_filesz);
		READ_XWORD(s,t.p_memsz);
		READ_XWORD(s,t.p_align);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Phdr */
			SWAP_WORD(t.p_type);
			SWAP_WORD(t.p_flags);
			SWAP_OFF64(t.p_offset);
			SWAP_ADDR64(t.p_vaddr);
			SWAP_ADDR64(t.p_paddr);
			SWAP_XWORD(t.p_filesz);
			SWAP_XWORD(t.p_memsz);
			SWAP_XWORD(t.p_align);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_REL32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Rel	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Rel *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Rel */
			SWAP_ADDR32(t.r_offset);
			SWAP_WORD(t.r_info);
			/**/
		}
		/* Write an Elf32_Rel */
		WRITE_ADDR32(dst,t.r_offset);
		WRITE_WORD(dst,t.r_info);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_REL32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Rel	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_REL, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Rel *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Rel))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Rel */
		READ_ADDR32(s,t.r_offset);
		READ_WORD(s,t.r_info);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Rel */
			SWAP_ADDR32(t.r_offset);
			SWAP_WORD(t.r_info);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_REL64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Rel	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Rel *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Rel */
			SWAP_ADDR64(t.r_offset);
			SWAP_XWORD(t.r_info);
			/**/
		}
		/* Write an Elf64_Rel */
		WRITE_ADDR64(dst,t.r_offset);
		WRITE_XWORD(dst,t.r_info);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_REL64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Rel	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_REL, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Rel *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Rel))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Rel */
		READ_ADDR64(s,t.r_offset);
		READ_XWORD(s,t.r_info);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Rel */
			SWAP_ADDR64(t.r_offset);
			SWAP_XWORD(t.r_info);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_RELA32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Rela	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Rela *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Rela */
			SWAP_ADDR32(t.r_offset);
			SWAP_WORD(t.r_info);
			SWAP_SWORD(t.r_addend);
			/**/
		}
		/* Write an Elf32_Rela */
		WRITE_ADDR32(dst,t.r_offset);
		WRITE_WORD(dst,t.r_info);
		WRITE_SWORD(dst,t.r_addend);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_RELA32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Rela	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_RELA, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Rela *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Rela))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Rela */
		READ_ADDR32(s,t.r_offset);
		READ_WORD(s,t.r_info);
		READ_SWORD(s,t.r_addend);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Rela */
			SWAP_ADDR32(t.r_offset);
			SWAP_WORD(t.r_info);
			SWAP_SWORD(t.r_addend);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_RELA64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Rela	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Rela *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Rela */
			SWAP_ADDR64(t.r_offset);
			SWAP_XWORD(t.r_info);
			SWAP_SXWORD(t.r_addend);
			/**/
		}
		/* Write an Elf64_Rela */
		WRITE_ADDR64(dst,t.r_offset);
		WRITE_XWORD(dst,t.r_info);
		WRITE_SXWORD(dst,t.r_addend);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_RELA64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Rela	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_RELA, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Rela *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Rela))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Rela */
		READ_ADDR64(s,t.r_offset);
		READ_XWORD(s,t.r_info);
		READ_SXWORD(s,t.r_addend);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Rela */
			SWAP_ADDR64(t.r_offset);
			SWAP_XWORD(t.r_info);
			SWAP_SXWORD(t.r_addend);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_SHDR32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Shdr	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Shdr *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Shdr */
			SWAP_WORD(t.sh_name);
			SWAP_WORD(t.sh_type);
			SWAP_WORD(t.sh_flags);
			SWAP_ADDR32(t.sh_addr);
			SWAP_OFF32(t.sh_offset);
			SWAP_WORD(t.sh_size);
			SWAP_WORD(t.sh_link);
			SWAP_WORD(t.sh_info);
			SWAP_WORD(t.sh_addralign);
			SWAP_WORD(t.sh_entsize);
			/**/
		}
		/* Write an Elf32_Shdr */
		WRITE_WORD(dst,t.sh_name);
		WRITE_WORD(dst,t.sh_type);
		WRITE_WORD(dst,t.sh_flags);
		WRITE_ADDR32(dst,t.sh_addr);
		WRITE_OFF32(dst,t.sh_offset);
		WRITE_WORD(dst,t.sh_size);
		WRITE_WORD(dst,t.sh_link);
		WRITE_WORD(dst,t.sh_info);
		WRITE_WORD(dst,t.sh_addralign);
		WRITE_WORD(dst,t.sh_entsize);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_SHDR32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Shdr	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_SHDR, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Shdr *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Shdr))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Shdr */
		READ_WORD(s,t.sh_name);
		READ_WORD(s,t.sh_type);
		READ_WORD(s,t.sh_flags);
		READ_ADDR32(s,t.sh_addr);
		READ_OFF32(s,t.sh_offset);
		READ_WORD(s,t.sh_size);
		READ_WORD(s,t.sh_link);
		READ_WORD(s,t.sh_info);
		READ_WORD(s,t.sh_addralign);
		READ_WORD(s,t.sh_entsize);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Shdr */
			SWAP_WORD(t.sh_name);
			SWAP_WORD(t.sh_type);
			SWAP_WORD(t.sh_flags);
			SWAP_ADDR32(t.sh_addr);
			SWAP_OFF32(t.sh_offset);
			SWAP_WORD(t.sh_size);
			SWAP_WORD(t.sh_link);
			SWAP_WORD(t.sh_info);
			SWAP_WORD(t.sh_addralign);
			SWAP_WORD(t.sh_entsize);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_SHDR64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Shdr	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Shdr *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Shdr */
			SWAP_WORD(t.sh_name);
			SWAP_WORD(t.sh_type);
			SWAP_XWORD(t.sh_flags);
			SWAP_ADDR64(t.sh_addr);
			SWAP_OFF64(t.sh_offset);
			SWAP_XWORD(t.sh_size);
			SWAP_WORD(t.sh_link);
			SWAP_WORD(t.sh_info);
			SWAP_XWORD(t.sh_addralign);
			SWAP_XWORD(t.sh_entsize);
			/**/
		}
		/* Write an Elf64_Shdr */
		WRITE_WORD(dst,t.sh_name);
		WRITE_WORD(dst,t.sh_type);
		WRITE_XWORD(dst,t.sh_flags);
		WRITE_ADDR64(dst,t.sh_addr);
		WRITE_OFF64(dst,t.sh_offset);
		WRITE_XWORD(dst,t.sh_size);
		WRITE_WORD(dst,t.sh_link);
		WRITE_WORD(dst,t.sh_info);
		WRITE_XWORD(dst,t.sh_addralign);
		WRITE_XWORD(dst,t.sh_entsize);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_SHDR64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Shdr	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_SHDR, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Shdr *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Shdr))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Shdr */
		READ_WORD(s,t.sh_name);
		READ_WORD(s,t.sh_type);
		READ_XWORD(s,t.sh_flags);
		READ_ADDR64(s,t.sh_addr);
		READ_OFF64(s,t.sh_offset);
		READ_XWORD(s,t.sh_size);
		READ_WORD(s,t.sh_link);
		READ_WORD(s,t.sh_info);
		READ_XWORD(s,t.sh_addralign);
		READ_XWORD(s,t.sh_entsize);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Shdr */
			SWAP_WORD(t.sh_name);
			SWAP_WORD(t.sh_type);
			SWAP_XWORD(t.sh_flags);
			SWAP_ADDR64(t.sh_addr);
			SWAP_OFF64(t.sh_offset);
			SWAP_XWORD(t.sh_size);
			SWAP_WORD(t.sh_link);
			SWAP_WORD(t.sh_info);
			SWAP_XWORD(t.sh_addralign);
			SWAP_XWORD(t.sh_entsize);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_SWORD_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Sword t, *s = (Elf64_Sword *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_SWORD(t);
		WRITE_SWORD(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_SWORD_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Sword t, *d = (Elf64_Sword *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Sword))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_SWORD(src,t);
		SWAP_SWORD(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_SXWORD_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Sxword t, *s = (Elf64_Sxword *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_SXWORD(t);
		WRITE_SXWORD(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_SXWORD_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Sxword t, *d = (Elf64_Sxword *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Sxword))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_SXWORD(src,t);
		SWAP_SXWORD(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_SYMINFO32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Syminfo	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Syminfo *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Syminfo */
			SWAP_HALF(t.si_boundto);
			SWAP_HALF(t.si_flags);
			/**/
		}
		/* Write an Elf32_Syminfo */
		WRITE_HALF(dst,t.si_boundto);
		WRITE_HALF(dst,t.si_flags);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_SYMINFO32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Syminfo	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_SYMINFO, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Syminfo *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Syminfo))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Syminfo */
		READ_HALF(s,t.si_boundto);
		READ_HALF(s,t.si_flags);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Syminfo */
			SWAP_HALF(t.si_boundto);
			SWAP_HALF(t.si_flags);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_SYMINFO64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Syminfo	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Syminfo *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Syminfo */
			SWAP_HALF(t.si_boundto);
			SWAP_HALF(t.si_flags);
			/**/
		}
		/* Write an Elf64_Syminfo */
		WRITE_HALF(dst,t.si_boundto);
		WRITE_HALF(dst,t.si_flags);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_SYMINFO64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Syminfo	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_SYMINFO, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Syminfo *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Syminfo))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Syminfo */
		READ_HALF(s,t.si_boundto);
		READ_HALF(s,t.si_flags);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Syminfo */
			SWAP_HALF(t.si_boundto);
			SWAP_HALF(t.si_flags);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_SYM32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Sym	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf32_Sym *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf32_Sym */
			SWAP_WORD(t.st_name);
			SWAP_ADDR32(t.st_value);
			SWAP_WORD(t.st_size);
			SWAP_BYTE(t.st_info);
			SWAP_BYTE(t.st_other);
			SWAP_HALF(t.st_shndx);
			/**/
		}
		/* Write an Elf32_Sym */
		WRITE_WORD(dst,t.st_name);
		WRITE_ADDR32(dst,t.st_value);
		WRITE_WORD(dst,t.st_size);
		WRITE_BYTE(dst,t.st_info);
		WRITE_BYTE(dst,t.st_other);
		WRITE_HALF(dst,t.st_shndx);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_SYM32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Sym	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf32_fsize(ELF_T_SYM, (size_t) 1, EV_CURRENT);
	d   = ((Elf32_Sym *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf32_Sym))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf32_Sym */
		READ_WORD(s,t.st_name);
		READ_ADDR32(s,t.st_value);
		READ_WORD(s,t.st_size);
		READ_BYTE(s,t.st_info);
		READ_BYTE(s,t.st_other);
		READ_HALF(s,t.st_shndx);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Sym */
			SWAP_WORD(t.st_name);
			SWAP_ADDR32(t.st_value);
			SWAP_WORD(t.st_size);
			SWAP_BYTE(t.st_info);
			SWAP_BYTE(t.st_other);
			SWAP_HALF(t.st_shndx);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}
       
static int
_libelf_cvt_SYM64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Sym	t, *s;
	size_t c;

	(void) dsz;

	s = (Elf64_Sym *) (uintptr_t) src;
	for (c = 0; c < count; c++) {
		t = *s++;
		if (byteswap) {
			/* Swap an Elf64_Sym */
			SWAP_WORD(t.st_name);
			SWAP_BYTE(t.st_info);
			SWAP_BYTE(t.st_other);
			SWAP_HALF(t.st_shndx);
			SWAP_ADDR64(t.st_value);
			SWAP_XWORD(t.st_size);
			/**/
		}
		/* Write an Elf64_Sym */
		WRITE_WORD(dst,t.st_name);
		WRITE_BYTE(dst,t.st_info);
		WRITE_BYTE(dst,t.st_other);
		WRITE_HALF(dst,t.st_shndx);
		WRITE_ADDR64(dst,t.st_value);
		WRITE_XWORD(dst,t.st_size);
		/**/
	}

	return (1);
}

static int
_libelf_cvt_SYM64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Sym	t, *d;
	unsigned char	*s,*s0;
	size_t		fsz;

	fsz = elf64_fsize(ELF_T_SYM, (size_t) 1, EV_CURRENT);
	d   = ((Elf64_Sym *) (uintptr_t) dst) + (count - 1);
	s0  = src + (count - 1) * fsz;

	if (dsz < count * sizeof(Elf64_Sym))
		return (0);

	while (count--) {
		s = s0;
		/* Read an Elf64_Sym */
		READ_WORD(s,t.st_name);
		READ_BYTE(s,t.st_info);
		READ_BYTE(s,t.st_other);
		READ_HALF(s,t.st_shndx);
		READ_ADDR64(s,t.st_value);
		READ_XWORD(s,t.st_size);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Sym */
			SWAP_WORD(t.st_name);
			SWAP_BYTE(t.st_info);
			SWAP_BYTE(t.st_other);
			SWAP_HALF(t.st_shndx);
			SWAP_ADDR64(t.st_value);
			SWAP_XWORD(t.st_size);
			/**/
		}
		*d-- = t; s0 -= fsz;
	}

	return (1);
}

static int
_libelf_cvt_WORD_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Word t, *s = (Elf64_Word *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_WORD(t);
		WRITE_WORD(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_WORD_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Word t, *d = (Elf64_Word *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Word))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_WORD(src,t);
		SWAP_WORD(t);
		*d++ = t;
	}

	return (1);
}

static int
_libelf_cvt_XWORD_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Xword t, *s = (Elf64_Xword *) (uintptr_t) src;
	size_t c;

	(void) dsz;

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*s));
		return (1);
	}

	for (c = 0; c < count; c++) {
		t = *s++;
		SWAP_XWORD(t);
		WRITE_XWORD(dst,t);
	}

	return (1);
}

static int
_libelf_cvt_XWORD_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Xword t, *d = (Elf64_Xword *) (uintptr_t) dst;
	size_t c;

	if (dsz < count * sizeof(Elf64_Xword))
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count * sizeof(*d));
		return (1);
	}

	for (c = 0; c < count; c++) {
		READ_XWORD(src,t);
		SWAP_XWORD(t);
		*d++ = t;
	}

	return (1);
}


static int
_libelf_cvt_VDEF32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Verdef	t;
	Elf32_Verdaux	a;
	const size_t	verfsz = 20;
	const size_t	auxfsz = 8;
	const size_t	vermsz = sizeof(Elf32_Verdef);
	const size_t	auxmsz = sizeof(Elf32_Verdaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dtmp, *dstaux, *srcaux;
	Elf32_Word	aux, anext, cnt, vnext;

	for (dtmp = dst, vnext = ~0U;
	     vnext != 0 && dtmp + verfsz <= dstend && src + vermsz <= srcend;
	     dtmp += vnext, src += vnext) {

		/* Read in an Elf32_Verdef structure. */
		t = *((Elf32_Verdef *) (uintptr_t) src);

		aux = t.vd_aux;
		cnt = t.vd_cnt;
		vnext = t.vd_next;

		if (byteswap) {
			/* Swap an Elf32_Verdef */
			SWAP_HALF(t.vd_version);
			SWAP_HALF(t.vd_flags);
			SWAP_HALF(t.vd_ndx);
			SWAP_HALF(t.vd_cnt);
			SWAP_WORD(t.vd_hash);
			SWAP_WORD(t.vd_aux);
			SWAP_WORD(t.vd_next);
			/**/
		}

		dst = dtmp;
		/* Write an Elf32_Verdef */
		WRITE_HALF(dst,t.vd_version);
		WRITE_HALF(dst,t.vd_flags);
		WRITE_HALF(dst,t.vd_ndx);
		WRITE_HALF(dst,t.vd_cnt);
		WRITE_WORD(dst,t.vd_hash);
		WRITE_WORD(dst,t.vd_aux);
		WRITE_WORD(dst,t.vd_next);
		/**/

		if (aux < verfsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dtmp + aux, srcaux = src + aux;
		     cnt != 0 && anext != 0 && dstaux + auxfsz <= dstend &&
			srcaux + auxmsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			/* Read in an Elf32_Verdaux structure. */
			a = *((Elf32_Verdaux *) (uintptr_t) srcaux);
			anext = a.vda_next;

			if (byteswap) {
				/* Swap an Elf32_Verdaux */
			SWAP_WORD(a.vda_name);
			SWAP_WORD(a.vda_next);
			/**/
			}

			dst = dstaux;
			/* Write an Elf32_Verdaux */
		WRITE_WORD(dst,a.vda_name);
		WRITE_WORD(dst,a.vda_next);
		/**/
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}

static int
_libelf_cvt_VDEF32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Verdef	t, *dp;
	Elf32_Verdaux	a, *ap;
	const size_t	verfsz = 20;
	const size_t	auxfsz = 8;
	const size_t	vermsz = sizeof(Elf32_Verdef);
	const size_t	auxmsz = sizeof(Elf32_Verdaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dstaux, *s, *srcaux, *stmp;
	Elf32_Word	aux, anext, cnt, vnext;

	for (stmp = src, vnext = ~0U;
	     vnext != 0 && stmp + verfsz <= srcend && dst + vermsz <= dstend;
	     stmp += vnext, dst += vnext) {

		/* Read in a VDEF structure. */
		s = stmp;
		/* Read an Elf32_Verdef */
		READ_HALF(s,t.vd_version);
		READ_HALF(s,t.vd_flags);
		READ_HALF(s,t.vd_ndx);
		READ_HALF(s,t.vd_cnt);
		READ_WORD(s,t.vd_hash);
		READ_WORD(s,t.vd_aux);
		READ_WORD(s,t.vd_next);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Verdef */
			SWAP_HALF(t.vd_version);
			SWAP_HALF(t.vd_flags);
			SWAP_HALF(t.vd_ndx);
			SWAP_HALF(t.vd_cnt);
			SWAP_WORD(t.vd_hash);
			SWAP_WORD(t.vd_aux);
			SWAP_WORD(t.vd_next);
			/**/
		}

		dp = (Elf32_Verdef *) (uintptr_t) dst;
		*dp = t;

		aux = t.vd_aux;
		cnt = t.vd_cnt;
		vnext = t.vd_next;

		if (aux < vermsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dst + aux, srcaux = stmp + aux;
		     cnt != 0 && anext != 0 && dstaux + auxmsz <= dstend &&
			srcaux + auxfsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			s = srcaux;
			/* Read an Elf32_Verdaux */
		READ_WORD(s,a.vda_name);
		READ_WORD(s,a.vda_next);
		/**/

			if (byteswap) {
				/* Swap an Elf32_Verdaux */
			SWAP_WORD(a.vda_name);
			SWAP_WORD(a.vda_next);
			/**/
			}

			anext = a.vda_next;

			ap = ((Elf32_Verdaux *) (uintptr_t) dstaux);
			*ap = a;
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}
   
static int
_libelf_cvt_VDEF64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Verdef	t;
	Elf64_Verdaux	a;
	const size_t	verfsz = 20;
	const size_t	auxfsz = 8;
	const size_t	vermsz = sizeof(Elf64_Verdef);
	const size_t	auxmsz = sizeof(Elf64_Verdaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dtmp, *dstaux, *srcaux;
	Elf64_Word	aux, anext, cnt, vnext;

	for (dtmp = dst, vnext = ~0U;
	     vnext != 0 && dtmp + verfsz <= dstend && src + vermsz <= srcend;
	     dtmp += vnext, src += vnext) {

		/* Read in an Elf64_Verdef structure. */
		t = *((Elf64_Verdef *) (uintptr_t) src);

		aux = t.vd_aux;
		cnt = t.vd_cnt;
		vnext = t.vd_next;

		if (byteswap) {
			/* Swap an Elf64_Verdef */
			SWAP_HALF(t.vd_version);
			SWAP_HALF(t.vd_flags);
			SWAP_HALF(t.vd_ndx);
			SWAP_HALF(t.vd_cnt);
			SWAP_WORD(t.vd_hash);
			SWAP_WORD(t.vd_aux);
			SWAP_WORD(t.vd_next);
			/**/
		}

		dst = dtmp;
		/* Write an Elf64_Verdef */
		WRITE_HALF(dst,t.vd_version);
		WRITE_HALF(dst,t.vd_flags);
		WRITE_HALF(dst,t.vd_ndx);
		WRITE_HALF(dst,t.vd_cnt);
		WRITE_WORD(dst,t.vd_hash);
		WRITE_WORD(dst,t.vd_aux);
		WRITE_WORD(dst,t.vd_next);
		/**/

		if (aux < verfsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dtmp + aux, srcaux = src + aux;
		     cnt != 0 && anext != 0 && dstaux + auxfsz <= dstend &&
			srcaux + auxmsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			/* Read in an Elf64_Verdaux structure. */
			a = *((Elf64_Verdaux *) (uintptr_t) srcaux);
			anext = a.vda_next;

			if (byteswap) {
				/* Swap an Elf64_Verdaux */
			SWAP_WORD(a.vda_name);
			SWAP_WORD(a.vda_next);
			/**/
			}

			dst = dstaux;
			/* Write an Elf64_Verdaux */
		WRITE_WORD(dst,a.vda_name);
		WRITE_WORD(dst,a.vda_next);
		/**/
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}

static int
_libelf_cvt_VDEF64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Verdef	t, *dp;
	Elf64_Verdaux	a, *ap;
	const size_t	verfsz = 20;
	const size_t	auxfsz = 8;
	const size_t	vermsz = sizeof(Elf64_Verdef);
	const size_t	auxmsz = sizeof(Elf64_Verdaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dstaux, *s, *srcaux, *stmp;
	Elf64_Word	aux, anext, cnt, vnext;

	for (stmp = src, vnext = ~0U;
	     vnext != 0 && stmp + verfsz <= srcend && dst + vermsz <= dstend;
	     stmp += vnext, dst += vnext) {

		/* Read in a VDEF structure. */
		s = stmp;
		/* Read an Elf64_Verdef */
		READ_HALF(s,t.vd_version);
		READ_HALF(s,t.vd_flags);
		READ_HALF(s,t.vd_ndx);
		READ_HALF(s,t.vd_cnt);
		READ_WORD(s,t.vd_hash);
		READ_WORD(s,t.vd_aux);
		READ_WORD(s,t.vd_next);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Verdef */
			SWAP_HALF(t.vd_version);
			SWAP_HALF(t.vd_flags);
			SWAP_HALF(t.vd_ndx);
			SWAP_HALF(t.vd_cnt);
			SWAP_WORD(t.vd_hash);
			SWAP_WORD(t.vd_aux);
			SWAP_WORD(t.vd_next);
			/**/
		}

		dp = (Elf64_Verdef *) (uintptr_t) dst;
		*dp = t;

		aux = t.vd_aux;
		cnt = t.vd_cnt;
		vnext = t.vd_next;

		if (aux < vermsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dst + aux, srcaux = stmp + aux;
		     cnt != 0 && anext != 0 && dstaux + auxmsz <= dstend &&
			srcaux + auxfsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			s = srcaux;
			/* Read an Elf64_Verdaux */
		READ_WORD(s,a.vda_name);
		READ_WORD(s,a.vda_next);
		/**/

			if (byteswap) {
				/* Swap an Elf64_Verdaux */
			SWAP_WORD(a.vda_name);
			SWAP_WORD(a.vda_next);
			/**/
			}

			anext = a.vda_next;

			ap = ((Elf64_Verdaux *) (uintptr_t) dstaux);
			*ap = a;
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}

static int
_libelf_cvt_VNEED32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Verneed	t;
	Elf32_Vernaux	a;
	const size_t	verfsz = 16;
	const size_t	auxfsz = 16;
	const size_t	vermsz = sizeof(Elf32_Verneed);
	const size_t	auxmsz = sizeof(Elf32_Vernaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dtmp, *dstaux, *srcaux;
	Elf32_Word	aux, anext, cnt, vnext;

	for (dtmp = dst, vnext = ~0U;
	     vnext != 0 && dtmp + verfsz <= dstend && src + vermsz <= srcend;
	     dtmp += vnext, src += vnext) {

		/* Read in an Elf32_Verneed structure. */
		t = *((Elf32_Verneed *) (uintptr_t) src);

		aux = t.vn_aux;
		cnt = t.vn_cnt;
		vnext = t.vn_next;

		if (byteswap) {
			/* Swap an Elf32_Verneed */
			SWAP_HALF(t.vn_version);
			SWAP_HALF(t.vn_cnt);
			SWAP_WORD(t.vn_file);
			SWAP_WORD(t.vn_aux);
			SWAP_WORD(t.vn_next);
			/**/
		}

		dst = dtmp;
		/* Write an Elf32_Verneed */
		WRITE_HALF(dst,t.vn_version);
		WRITE_HALF(dst,t.vn_cnt);
		WRITE_WORD(dst,t.vn_file);
		WRITE_WORD(dst,t.vn_aux);
		WRITE_WORD(dst,t.vn_next);
		/**/

		if (aux < verfsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dtmp + aux, srcaux = src + aux;
		     cnt != 0 && anext != 0 && dstaux + auxfsz <= dstend &&
			srcaux + auxmsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			/* Read in an Elf32_Vernaux structure. */
			a = *((Elf32_Vernaux *) (uintptr_t) srcaux);
			anext = a.vna_next;

			if (byteswap) {
				/* Swap an Elf32_Vernaux */
			SWAP_WORD(a.vna_hash);
			SWAP_HALF(a.vna_flags);
			SWAP_HALF(a.vna_other);
			SWAP_WORD(a.vna_name);
			SWAP_WORD(a.vna_next);
			/**/
			}

			dst = dstaux;
			/* Write an Elf32_Vernaux */
		WRITE_WORD(dst,a.vna_hash);
		WRITE_HALF(dst,a.vna_flags);
		WRITE_HALF(dst,a.vna_other);
		WRITE_WORD(dst,a.vna_name);
		WRITE_WORD(dst,a.vna_next);
		/**/
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}

static int
_libelf_cvt_VNEED32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf32_Verneed	t, *dp;
	Elf32_Vernaux	a, *ap;
	const size_t	verfsz = 16;
	const size_t	auxfsz = 16;
	const size_t	vermsz = sizeof(Elf32_Verneed);
	const size_t	auxmsz = sizeof(Elf32_Vernaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dstaux, *s, *srcaux, *stmp;
	Elf32_Word	aux, anext, cnt, vnext;

	for (stmp = src, vnext = ~0U;
	     vnext != 0 && stmp + verfsz <= srcend && dst + vermsz <= dstend;
	     stmp += vnext, dst += vnext) {

		/* Read in a VNEED structure. */
		s = stmp;
		/* Read an Elf32_Verneed */
		READ_HALF(s,t.vn_version);
		READ_HALF(s,t.vn_cnt);
		READ_WORD(s,t.vn_file);
		READ_WORD(s,t.vn_aux);
		READ_WORD(s,t.vn_next);
		/**/
		if (byteswap) {
			/* Swap an Elf32_Verneed */
			SWAP_HALF(t.vn_version);
			SWAP_HALF(t.vn_cnt);
			SWAP_WORD(t.vn_file);
			SWAP_WORD(t.vn_aux);
			SWAP_WORD(t.vn_next);
			/**/
		}

		dp = (Elf32_Verneed *) (uintptr_t) dst;
		*dp = t;

		aux = t.vn_aux;
		cnt = t.vn_cnt;
		vnext = t.vn_next;

		if (aux < vermsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dst + aux, srcaux = stmp + aux;
		     cnt != 0 && anext != 0 && dstaux + auxmsz <= dstend &&
			srcaux + auxfsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			s = srcaux;
			/* Read an Elf32_Vernaux */
		READ_WORD(s,a.vna_hash);
		READ_HALF(s,a.vna_flags);
		READ_HALF(s,a.vna_other);
		READ_WORD(s,a.vna_name);
		READ_WORD(s,a.vna_next);
		/**/

			if (byteswap) {
				/* Swap an Elf32_Vernaux */
			SWAP_WORD(a.vna_hash);
			SWAP_HALF(a.vna_flags);
			SWAP_HALF(a.vna_other);
			SWAP_WORD(a.vna_name);
			SWAP_WORD(a.vna_next);
			/**/
			}

			anext = a.vna_next;

			ap = ((Elf32_Vernaux *) (uintptr_t) dstaux);
			*ap = a;
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}
   
static int
_libelf_cvt_VNEED64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Verneed	t;
	Elf64_Vernaux	a;
	const size_t	verfsz = 16;
	const size_t	auxfsz = 16;
	const size_t	vermsz = sizeof(Elf64_Verneed);
	const size_t	auxmsz = sizeof(Elf64_Vernaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dtmp, *dstaux, *srcaux;
	Elf64_Word	aux, anext, cnt, vnext;

	for (dtmp = dst, vnext = ~0U;
	     vnext != 0 && dtmp + verfsz <= dstend && src + vermsz <= srcend;
	     dtmp += vnext, src += vnext) {

		/* Read in an Elf64_Verneed structure. */
		t = *((Elf64_Verneed *) (uintptr_t) src);

		aux = t.vn_aux;
		cnt = t.vn_cnt;
		vnext = t.vn_next;

		if (byteswap) {
			/* Swap an Elf64_Verneed */
			SWAP_HALF(t.vn_version);
			SWAP_HALF(t.vn_cnt);
			SWAP_WORD(t.vn_file);
			SWAP_WORD(t.vn_aux);
			SWAP_WORD(t.vn_next);
			/**/
		}

		dst = dtmp;
		/* Write an Elf64_Verneed */
		WRITE_HALF(dst,t.vn_version);
		WRITE_HALF(dst,t.vn_cnt);
		WRITE_WORD(dst,t.vn_file);
		WRITE_WORD(dst,t.vn_aux);
		WRITE_WORD(dst,t.vn_next);
		/**/

		if (aux < verfsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dtmp + aux, srcaux = src + aux;
		     cnt != 0 && anext != 0 && dstaux + auxfsz <= dstend &&
			srcaux + auxmsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			/* Read in an Elf64_Vernaux structure. */
			a = *((Elf64_Vernaux *) (uintptr_t) srcaux);
			anext = a.vna_next;

			if (byteswap) {
				/* Swap an Elf64_Vernaux */
			SWAP_WORD(a.vna_hash);
			SWAP_HALF(a.vna_flags);
			SWAP_HALF(a.vna_other);
			SWAP_WORD(a.vna_name);
			SWAP_WORD(a.vna_next);
			/**/
			}

			dst = dstaux;
			/* Write an Elf64_Vernaux */
		WRITE_WORD(dst,a.vna_hash);
		WRITE_HALF(dst,a.vna_flags);
		WRITE_HALF(dst,a.vna_other);
		WRITE_WORD(dst,a.vna_name);
		WRITE_WORD(dst,a.vna_next);
		/**/
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}

static int
_libelf_cvt_VNEED64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	Elf64_Verneed	t, *dp;
	Elf64_Vernaux	a, *ap;
	const size_t	verfsz = 16;
	const size_t	auxfsz = 16;
	const size_t	vermsz = sizeof(Elf64_Verneed);
	const size_t	auxmsz = sizeof(Elf64_Vernaux);
	unsigned char * const dstend = dst + dsz;
	unsigned char * const srcend = src + count;
	unsigned char	*dstaux, *s, *srcaux, *stmp;
	Elf64_Word	aux, anext, cnt, vnext;

	for (stmp = src, vnext = ~0U;
	     vnext != 0 && stmp + verfsz <= srcend && dst + vermsz <= dstend;
	     stmp += vnext, dst += vnext) {

		/* Read in a VNEED structure. */
		s = stmp;
		/* Read an Elf64_Verneed */
		READ_HALF(s,t.vn_version);
		READ_HALF(s,t.vn_cnt);
		READ_WORD(s,t.vn_file);
		READ_WORD(s,t.vn_aux);
		READ_WORD(s,t.vn_next);
		/**/
		if (byteswap) {
			/* Swap an Elf64_Verneed */
			SWAP_HALF(t.vn_version);
			SWAP_HALF(t.vn_cnt);
			SWAP_WORD(t.vn_file);
			SWAP_WORD(t.vn_aux);
			SWAP_WORD(t.vn_next);
			/**/
		}

		dp = (Elf64_Verneed *) (uintptr_t) dst;
		*dp = t;

		aux = t.vn_aux;
		cnt = t.vn_cnt;
		vnext = t.vn_next;

		if (aux < vermsz)
			return (0);

		/* Process AUX entries. */
		for (anext = ~0U, dstaux = dst + aux, srcaux = stmp + aux;
		     cnt != 0 && anext != 0 && dstaux + auxmsz <= dstend &&
			srcaux + auxfsz <= srcend;
		     dstaux += anext, srcaux += anext, cnt--) {

			s = srcaux;
			/* Read an Elf64_Vernaux */
		READ_WORD(s,a.vna_hash);
		READ_HALF(s,a.vna_flags);
		READ_HALF(s,a.vna_other);
		READ_WORD(s,a.vna_name);
		READ_WORD(s,a.vna_next);
		/**/

			if (byteswap) {
				/* Swap an Elf64_Vernaux */
			SWAP_WORD(a.vna_hash);
			SWAP_HALF(a.vna_flags);
			SWAP_HALF(a.vna_other);
			SWAP_WORD(a.vna_name);
			SWAP_WORD(a.vna_next);
			/**/
			}

			anext = a.vna_next;

			ap = ((Elf64_Vernaux *) (uintptr_t) dstaux);
			*ap = a;
		}

		if (anext || cnt)
			return (0);
	}

	if (vnext)
		return (0);

	return (1);
}
/*]*/

/*
 * Sections of type ELF_T_BYTE are never byteswapped, consequently a
 * simple memcpy suffices for both directions of conversion.
 */

static int
_libelf_cvt_BYTE_tox(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	(void) byteswap;
	if (dsz < count)
		return (0);
	if (dst != src)
		(void) memcpy(dst, src, count);
	return (1);
}

/*
 * Sections of type ELF_T_GNUHASH start with a header containing 4 32-bit
 * words.  Bloom filter data comes next, followed by hash buckets and the
 * hash chain.
 *
 * Bloom filter words are 64 bit wide on ELFCLASS64 objects and are 32 bit
 * wide on ELFCLASS32 objects.  The other objects in this section are 32
 * bits wide.
 *
 * Argument srcsz denotes the number of bytes to be converted.  In the
 * 32-bit case we need to translate srcsz to a count of 32-bit words.
 */

static int
_libelf_cvt_GNUHASH32_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t srcsz, int byteswap)
{
	return (_libelf_cvt_WORD_tom(dst, dsz, src, srcsz / sizeof(uint32_t),
		byteswap));
}

static int
_libelf_cvt_GNUHASH32_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t srcsz, int byteswap)
{
	return (_libelf_cvt_WORD_tof(dst, dsz, src, srcsz / sizeof(uint32_t),
		byteswap));
}

static int
_libelf_cvt_GNUHASH64_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t srcsz, int byteswap)
{
	size_t sz;
	uint64_t t64, *bloom64;
	Elf_GNU_Hash_Header *gh;
	uint32_t n, nbuckets, nchains, maskwords, shift2, symndx, t32;
	uint32_t *buckets, *chains;

	sz = 4 * sizeof(uint32_t);	/* File header is 4 words long. */
	if (dsz < sizeof(Elf_GNU_Hash_Header) || srcsz < sz)
		return (0);

	/* Read in the section header and byteswap if needed. */
	READ_WORD(src, nbuckets);
	READ_WORD(src, symndx);
	READ_WORD(src, maskwords);
	READ_WORD(src, shift2);

	srcsz -= sz;

	if (byteswap) {
		SWAP_WORD(nbuckets);
		SWAP_WORD(symndx);
		SWAP_WORD(maskwords);
		SWAP_WORD(shift2);
	}

	/* Check source buffer and destination buffer sizes. */
	sz = nbuckets * sizeof(uint32_t) + maskwords * sizeof(uint64_t);
	if (srcsz < sz || dsz < sz + sizeof(Elf_GNU_Hash_Header))
		return (0);

	gh = (Elf_GNU_Hash_Header *) (uintptr_t) dst;
	gh->gh_nbuckets  = nbuckets;
	gh->gh_symndx    = symndx;
	gh->gh_maskwords = maskwords;
	gh->gh_shift2    = shift2;

	dsz -= sizeof(Elf_GNU_Hash_Header);
	dst += sizeof(Elf_GNU_Hash_Header);

	bloom64 = (uint64_t *) (uintptr_t) dst;

	/* Copy bloom filter data. */
	for (n = 0; n < maskwords; n++) {
		READ_XWORD(src, t64);
		if (byteswap)
			SWAP_XWORD(t64);
		bloom64[n] = t64;
	}

	/* The hash buckets follows the bloom filter. */
	dst += maskwords * sizeof(uint64_t);
	buckets = (uint32_t *) (uintptr_t) dst;

	for (n = 0; n < nbuckets; n++) {
		READ_WORD(src, t32);
		if (byteswap)
			SWAP_WORD(t32);
		buckets[n] = t32;
	}

	dst += nbuckets * sizeof(uint32_t);

	/* The hash chain follows the hash buckets. */
	dsz -= sz;
	srcsz -= sz;

	if (dsz < srcsz)	/* Destination lacks space. */
		return (0);

	nchains = (uint32_t) (srcsz / sizeof(uint32_t));
	chains = (uint32_t *) (uintptr_t) dst;

	for (n = 0; n < nchains; n++) {
		READ_WORD(src, t32);
		if (byteswap)
			SWAP_WORD(t32);
		*chains++ = t32;
	}

	return (1);
}

static int
_libelf_cvt_GNUHASH64_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t srcsz, int byteswap)
{
	uint32_t *s32;
	size_t sz, hdrsz;
	uint64_t *s64, t64;
	Elf_GNU_Hash_Header *gh;
	uint32_t maskwords, n, nbuckets, nchains, t0, t1, t2, t3, t32;

	hdrsz = 4 * sizeof(uint32_t);	/* Header is 4x32 bits. */
	if (dsz < hdrsz || srcsz < sizeof(Elf_GNU_Hash_Header))
		return (0);

	gh = (Elf_GNU_Hash_Header *) (uintptr_t) src;

	t0 = nbuckets = gh->gh_nbuckets;
	t1 = gh->gh_symndx;
	t2 = maskwords = gh->gh_maskwords;
	t3 = gh->gh_shift2;

	src   += sizeof(Elf_GNU_Hash_Header);
	srcsz -= sizeof(Elf_GNU_Hash_Header);
	dsz   -= hdrsz;

	sz = gh->gh_nbuckets * sizeof(uint32_t) + gh->gh_maskwords *
	    sizeof(uint64_t);

	if (srcsz < sz || dsz < sz)
		return (0);

	/* Write out the header. */
	if (byteswap) {
		SWAP_WORD(t0);
		SWAP_WORD(t1);
		SWAP_WORD(t2);
		SWAP_WORD(t3);
	}

	WRITE_WORD(dst, t0);
	WRITE_WORD(dst, t1);
	WRITE_WORD(dst, t2);
	WRITE_WORD(dst, t3);

	/* Copy the bloom filter and the hash table. */
	s64 = (uint64_t *) (uintptr_t) src;
	for (n = 0; n < maskwords; n++) {
		t64 = *s64++;
		if (byteswap)
			SWAP_XWORD(t64);
		WRITE_WORD64(dst, t64);
	}

	s32 = (uint32_t *) s64;
	for (n = 0; n < nbuckets; n++) {
		t32 = *s32++;
		if (byteswap)
			SWAP_WORD(t32);
		WRITE_WORD(dst, t32);
	}

	srcsz -= sz;
	dsz   -= sz;

	/* Copy out the hash chains. */
	if (dsz < srcsz)
		return (0);

	nchains = (uint32_t) (srcsz / sizeof(uint32_t));
	for (n = 0; n < nchains; n++) {
		t32 = *s32++;
		if (byteswap)
			SWAP_WORD(t32);
		WRITE_WORD(dst, t32);
	}

	return (1);
}

/*
 * Elf_Note structures comprise a fixed size header followed by variable
 * length strings.  The fixed size header needs to be byte swapped, but
 * not the strings.
 *
 * Argument count denotes the total number of bytes to be converted.
 * The destination buffer needs to be at least count bytes in size.
 */
static int
_libelf_cvt_NOTE_tom(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	uint32_t namesz, descsz, type;
	Elf_Note *en;
	size_t sz, hdrsz;

	if (dsz < count)	/* Destination buffer is too small. */
		return (0);

	hdrsz = 3 * sizeof(uint32_t);
	if (count < hdrsz)		/* Source too small. */
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count);
		return (1);
	}

	/* Process all notes in the section. */
	while (count > hdrsz) {
		/* Read the note header. */
		READ_WORD(src, namesz);
		READ_WORD(src, descsz);
		READ_WORD(src, type);

		/* Translate. */
		SWAP_WORD(namesz);
		SWAP_WORD(descsz);
		SWAP_WORD(type);

		/* Copy out the translated note header. */
		en = (Elf_Note *) (uintptr_t) dst;
		en->n_namesz = namesz;
		en->n_descsz = descsz;
		en->n_type = type;

		dsz -= sizeof(Elf_Note);
		dst += sizeof(Elf_Note);
		count -= hdrsz;

		ROUNDUP2(namesz, 4U);
		ROUNDUP2(descsz, 4U);

		sz = namesz + descsz;

		if (count < sz || dsz < sz)	/* Buffers are too small. */
			return (0);

		/* Copy the remainder of the note as-is. */
		(void) memcpy(dst, src, sz);

		src += sz;
		dst += sz;

		count -= sz;
		dsz -= sz;
	}

	return (1);
}

static int
_libelf_cvt_NOTE_tof(unsigned char *dst, size_t dsz, unsigned char *src,
    size_t count, int byteswap)
{
	uint32_t namesz, descsz, type;
	Elf_Note *en;
	size_t sz;

	if (dsz < count)
		return (0);

	if (!byteswap) {
		(void) memcpy(dst, src, count);
		return (1);
	}

	while (count > sizeof(Elf_Note)) {

		en = (Elf_Note *) (uintptr_t) src;
		namesz = en->n_namesz;
		descsz = en->n_descsz;
		type = en->n_type;

		sz = namesz;
		ROUNDUP2(sz, 4U);
		sz += descsz;
		ROUNDUP2(sz, 4U);

		SWAP_WORD(namesz);
		SWAP_WORD(descsz);
		SWAP_WORD(type);

		WRITE_WORD(dst, namesz);
		WRITE_WORD(dst, descsz);
		WRITE_WORD(dst, type);

		src += sizeof(Elf_Note);
		count -= sizeof(Elf_Note);

		if (count < sz)
			sz = count;

		/* Copy the remainder of the note as-is. */
		(void) memcpy(dst, src, sz);

		src += sz;
		dst += sz;
		count -= sz;
	}

	return (1);
}

struct converters {
	int	(*tof32)(unsigned char *dst, size_t dsz, unsigned char *src,
		    size_t cnt, int byteswap);
	int	(*tom32)(unsigned char *dst, size_t dsz, unsigned char *src,
		    size_t cnt, int byteswap);
	int	(*tof64)(unsigned char *dst, size_t dsz, unsigned char *src,
		    size_t cnt, int byteswap);
	int	(*tom64)(unsigned char *dst, size_t dsz, unsigned char *src,
		    size_t cnt, int byteswap);
};


static struct converters cvt[ELF_T_NUM] = {
	/*[*/
	[ELF_T_ADDR] = {
		.tof32 = _libelf_cvt_ADDR32_tof,
		.tom32 = _libelf_cvt_ADDR32_tom,
		.tof64 = _libelf_cvt_ADDR64_tof,
		.tom64 = _libelf_cvt_ADDR64_tom
	},

	[ELF_T_CAP] = {
		.tof32 = _libelf_cvt_CAP32_tof,
		.tom32 = _libelf_cvt_CAP32_tom,
		.tof64 = _libelf_cvt_CAP64_tof,
		.tom64 = _libelf_cvt_CAP64_tom
	},

	[ELF_T_DYN] = {
		.tof32 = _libelf_cvt_DYN32_tof,
		.tom32 = _libelf_cvt_DYN32_tom,
		.tof64 = _libelf_cvt_DYN64_tof,
		.tom64 = _libelf_cvt_DYN64_tom
	},

	[ELF_T_EHDR] = {
		.tof32 = _libelf_cvt_EHDR32_tof,
		.tom32 = _libelf_cvt_EHDR32_tom,
		.tof64 = _libelf_cvt_EHDR64_tof,
		.tom64 = _libelf_cvt_EHDR64_tom
	},

	[ELF_T_GNUHASH] = {
		.tof32 = _libelf_cvt_GNUHASH32_tof,
		.tom32 = _libelf_cvt_GNUHASH32_tom,
		.tof64 = _libelf_cvt_GNUHASH64_tof,
		.tom64 = _libelf_cvt_GNUHASH64_tom
	},

	[ELF_T_HALF] = {
		.tof32 = _libelf_cvt_HALF_tof,
		.tom32 = _libelf_cvt_HALF_tom,
		.tof64 = _libelf_cvt_HALF_tof,
		.tom64 = _libelf_cvt_HALF_tom
	},

	[ELF_T_LWORD] = {
		.tof32 = _libelf_cvt_LWORD_tof,
		.tom32 = _libelf_cvt_LWORD_tom,
		.tof64 = _libelf_cvt_LWORD_tof,
		.tom64 = _libelf_cvt_LWORD_tom
	},

	[ELF_T_MOVE] = {
		.tof32 = _libelf_cvt_MOVE32_tof,
		.tom32 = _libelf_cvt_MOVE32_tom,
		.tof64 = _libelf_cvt_MOVE64_tof,
		.tom64 = _libelf_cvt_MOVE64_tom
	},

	[ELF_T_OFF] = {
		.tof32 = _libelf_cvt_OFF32_tof,
		.tom32 = _libelf_cvt_OFF32_tom,
		.tof64 = _libelf_cvt_OFF64_tof,
		.tom64 = _libelf_cvt_OFF64_tom
	},

	[ELF_T_PHDR] = {
		.tof32 = _libelf_cvt_PHDR32_tof,
		.tom32 = _libelf_cvt_PHDR32_tom,
		.tof64 = _libelf_cvt_PHDR64_tof,
		.tom64 = _libelf_cvt_PHDR64_tom
	},

	[ELF_T_REL] = {
		.tof32 = _libelf_cvt_REL32_tof,
		.tom32 = _libelf_cvt_REL32_tom,
		.tof64 = _libelf_cvt_REL64_tof,
		.tom64 = _libelf_cvt_REL64_tom
	},

	[ELF_T_RELA] = {
		.tof32 = _libelf_cvt_RELA32_tof,
		.tom32 = _libelf_cvt_RELA32_tom,
		.tof64 = _libelf_cvt_RELA64_tof,
		.tom64 = _libelf_cvt_RELA64_tom
	},

	[ELF_T_SHDR] = {
		.tof32 = _libelf_cvt_SHDR32_tof,
		.tom32 = _libelf_cvt_SHDR32_tom,
		.tof64 = _libelf_cvt_SHDR64_tof,
		.tom64 = _libelf_cvt_SHDR64_tom
	},

	[ELF_T_SWORD] = {
		.tof32 = _libelf_cvt_SWORD_tof,
		.tom32 = _libelf_cvt_SWORD_tom,
		.tof64 = _libelf_cvt_SWORD_tof,
		.tom64 = _libelf_cvt_SWORD_tom
	},

	[ELF_T_SXWORD] = {
		.tof32 = NULL,
		.tom32 = NULL,
		.tof64 = _libelf_cvt_SXWORD_tof,
		.tom64 = _libelf_cvt_SXWORD_tom
	},

	[ELF_T_SYMINFO] = {
		.tof32 = _libelf_cvt_SYMINFO32_tof,
		.tom32 = _libelf_cvt_SYMINFO32_tom,
		.tof64 = _libelf_cvt_SYMINFO64_tof,
		.tom64 = _libelf_cvt_SYMINFO64_tom
	},

	[ELF_T_SYM] = {
		.tof32 = _libelf_cvt_SYM32_tof,
		.tom32 = _libelf_cvt_SYM32_tom,
		.tof64 = _libelf_cvt_SYM64_tof,
		.tom64 = _libelf_cvt_SYM64_tom
	},

	[ELF_T_VDEF] = {
		.tof32 = _libelf_cvt_VDEF32_tof,
		.tom32 = _libelf_cvt_VDEF32_tom,
		.tof64 = _libelf_cvt_VDEF64_tof,
		.tom64 = _libelf_cvt_VDEF64_tom
	},

	[ELF_T_VNEED] = {
		.tof32 = _libelf_cvt_VNEED32_tof,
		.tom32 = _libelf_cvt_VNEED32_tom,
		.tof64 = _libelf_cvt_VNEED64_tof,
		.tom64 = _libelf_cvt_VNEED64_tom
	},

	[ELF_T_WORD] = {
		.tof32 = _libelf_cvt_WORD_tof,
		.tom32 = _libelf_cvt_WORD_tom,
		.tof64 = _libelf_cvt_WORD_tof,
		.tom64 = _libelf_cvt_WORD_tom
	},

	[ELF_T_XWORD] = {
		.tof32 = NULL,
		.tom32 = NULL,
		.tof64 = _libelf_cvt_XWORD_tof,
		.tom64 = _libelf_cvt_XWORD_tom
	},


	/*]*/

	/*
	 * Types that need hand-coded converters follow.
	 */

	[ELF_T_BYTE] = {
		.tof32 = _libelf_cvt_BYTE_tox,
		.tom32 = _libelf_cvt_BYTE_tox,
		.tof64 = _libelf_cvt_BYTE_tox,
		.tom64 = _libelf_cvt_BYTE_tox
	},

	[ELF_T_NOTE] = {
		.tof32 = _libelf_cvt_NOTE_tof,
		.tom32 = _libelf_cvt_NOTE_tom,
		.tof64 = _libelf_cvt_NOTE_tof,
		.tom64 = _libelf_cvt_NOTE_tom
	}
};

/*
 * Return a translator function for the specified ELF section type, conversion
 * direction, ELF class and ELF machine.
 */
_libelf_translator_function *
_libelf_get_translator(Elf_Type t, int direction, int elfclass, int elfmachine)
{
	assert(elfclass == ELFCLASS32 || elfclass == ELFCLASS64);
	assert(direction == ELF_TOFILE || direction == ELF_TOMEMORY);
	assert(t >= ELF_T_FIRST && t <= ELF_T_LAST);

	/* TODO: Handle MIPS64 REL{,A} sections (ticket #559). */
	(void) elfmachine;

	return ((elfclass == ELFCLASS32) ?
	    (direction == ELF_TOFILE ? cvt[t].tof32 : cvt[t].tom32) :
	    (direction == ELF_TOFILE ? cvt[t].tof64 : cvt[t].tom64));
}
