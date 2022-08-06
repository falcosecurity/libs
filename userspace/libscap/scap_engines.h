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

#include "scap_vtable.h"

#ifdef HAS_ENGINE_NODRIVER
extern const struct scap_vtable scap_nodriver_engine;
#endif

#ifdef HAS_ENGINE_SOURCE_PLUGIN
extern const struct scap_vtable scap_source_plugin_engine;
#endif

#ifdef HAS_ENGINE_SAVEFILE
extern const struct scap_vtable scap_savefile_engine;
#endif

#ifdef HAS_ENGINE_UDIG
extern const struct scap_vtable scap_udig_engine;
#endif

#ifdef HAS_ENGINE_BPF
extern const struct scap_vtable scap_bpf_engine;
#endif

#ifdef HAS_ENGINE_KMOD
extern const struct scap_vtable scap_kmod_engine;
#endif

#ifdef HAS_ENGINE_GVISOR
extern const struct scap_vtable scap_gvisor_engine;
#endif

#ifdef HAS_ENGINE_MODERN_BPF
extern const struct scap_vtable scap_modern_bpf_engine;
#endif

#ifdef HAS_ENGINE_TEST_INPUT
extern const struct scap_vtable scap_test_input_engine;
#endif
