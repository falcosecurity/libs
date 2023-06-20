/*
Copyright (C) 2022 The Falco Authors.

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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
int32_t scap_errprintf_unchecked(char *buf, int errnum, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));
#define scap_errprintf scap_errprintf_unchecked
#else

#include <stdio.h>

#define scap_errprintf(BUF, ERRNUM, ...) ((void)sizeof(printf(__VA_ARGS__)), scap_errprintf_unchecked(BUF, ERRNUM, __VA_ARGS__))
int32_t scap_errprintf_unchecked(char *buf, int errnum, const char* fmt, ...);
#endif

#ifdef __cplusplus
};
#endif
