// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#pragma once

#include <libscap/settings.h>

#if defined(USE_ZLIB)
#ifdef _WIN32
#define ZLIB_WINAPI
#endif
#include <zlib.h>
#else
#include <stdio.h>
#define	gzFile FILE*
#define gzflush(X, Y) fflush(X)
#define gzopen fopen
#define	gzdopen(fd, mode) fdopen(fd, mode)
#define gzclose fclose
#define gzoffset ftell
#define gzwrite(F, B, S) fwrite(B, 1, S, F)
#define gzread(F, B, S) fread(B, 1, S, F)
#define gztell(F) ftell(F)
inline static const char *gzerror(FILE *F, int *E) {*E = ferror(F); return "error reading file descriptor";}
#define gzseek fseek
#endif
