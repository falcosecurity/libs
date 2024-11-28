// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <gelf.h>

#include "_libelf.h"

#define NOTE_ALIGN(n)	(((n) + 3) & -4U)

size_t gelf_getnote(Elf_Data *data, size_t offset, GElf_Nhdr *result,
					size_t *name_offset, size_t *desc_offset) {
	if(data == NULL || data->d_type != ELF_T_NOTE) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return 0;
	}

	if(offset + sizeof(GElf_Nhdr) > data->d_size) {
		LIBELF_SET_ERROR(RANGE, 0);
		return 0;
	}

	const GElf_Nhdr *n = data->d_buf + offset;
	offset += sizeof(*n);

	GElf_Word namesz = NOTE_ALIGN(n->n_namesz);
	GElf_Word descsz = NOTE_ALIGN(n->n_descsz);

	if(data->d_size - offset < descsz) {
		return 0;
	}
	
	*name_offset = offset;
	offset += namesz;

	if (data->d_size - offset < descsz) {
		return 0;
	}

	*desc_offset = offset;
	offset += descsz;
	*result = *n;

	return offset;
}
