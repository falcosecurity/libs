# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

add_library(elf
	elf.c
	elf_begin.c
	elf_cntl.c
	elf_end.c
	elf_errmsg.c
	elf_errno.c
	elf_data.c
	elf_fill.c
	elf_flag.c
	elf_getarhdr.c
	elf_getarsym.c
	elf_getbase.c
	elf_getident.c
	elf_getversion.c
	elf_hash.c
	elf_kind.c
	elf_memory.c
	elf_next.c
	elf_open.c
	elf_rand.c
	elf_rawfile.c
	elf_phnum.c
	elf_shnum.c
	elf_shstrndx.c
	elf_scn.c
	elf_strptr.c
	elf_update.c
	elf_version.c
	gelf_cap.c
	gelf_checksum.c
	gelf_dyn.c
	gelf_ehdr.c
	gelf_getclass.c
	gelf_fsize.c
	gelf_move.c
	gelf_phdr.c
	gelf_rel.c
	gelf_rela.c
	gelf_shdr.c
	gelf_sym.c
	gelf_syminfo.c
	gelf_symshndx.c
	gelf_xlate.c
	libelf_align.c
	libelf_allocate.c
	libelf_ar.c
	libelf_ar_util.c
	libelf_checksum.c
	libelf_data.c
	libelf_ehdr.c
	libelf_elfmachine.c
	libelf_extended.c
	libelf_memory.c
	libelf_open.c
	libelf_phdr.c
	libelf_shdr.c
	libelf_xlate.c

	# the ones below are gensrcs, so they need to be generated beforehand

	libelf_fsize.c
	libelf_msize.c
	libelf_convert.c
)

target_compile_options(elf PRIVATE -Wno-unused-but-set-variable)
target_include_directories(elf PUBLIC ../common .)
