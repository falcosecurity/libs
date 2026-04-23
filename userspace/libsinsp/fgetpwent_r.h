// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

// On glibc, fgetpwent_r() and fgetgrent_r() are provided by the system.
// On other platforms (e.g. musl), we provide from-scratch implementations
// that parse /etc/passwd and /etc/group line-by-line into caller-owned storage.
//
// This header ensures that fgetpwent_r / fgetgrent_r are always available
// when HAVE_FGET__ENT is defined.

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#if defined(HAVE_PWD_H) || defined(HAVE_GRP_H)

#if defined(MUSL_OPTIMIZED) || defined(_DEFAULT_SOURCE) || defined(_SVID_SOURCE)
#ifndef HAVE_FGET__ENT
#define HAVE_FGET__ENT
#endif
#endif

#if defined(__GLIBC__) && defined(HAVE_FGET__ENT)
#ifndef HAVE_FGET__ENT_R
#define HAVE_FGET__ENT_R
#endif
#endif

#if defined(HAVE_FGET__ENT) && !defined(HAVE_FGET__ENT_R)

#include <cstdio>

#ifdef HAVE_PWD_H
int fgetpwent_r(FILE *f, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
#endif

#ifdef HAVE_GRP_H
int fgetgrent_r(FILE *f, struct group *grp, char *buf, size_t buflen, struct group **result);
#endif

#define HAVE_FGET__ENT_R
#endif

#endif  // HAVE_PWD_H || HAVE_GRP_H
