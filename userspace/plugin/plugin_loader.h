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

#include "plugin_api.h"

#ifdef __cplusplus
extern "C" {
#endif


/*!
    \brief The maximum length of the error strings written by the plugin loader
*/
#define PLUGIN_MAX_ERRLEN 2048

/*!
    \brief This enums the capabilities supported by plugins.
    Each plugin can support one or more of these, in which case the enum flags
    are or-ed with each other.
    Currently, the supported capabilities are:
        * ability to source events and provide them to the event loop
        * ability to extract fields from events created by other plugins
*/
typedef enum
{
    CAP_NONE        = 0,
    CAP_SOURCING    = 1 << 0,
    CAP_EXTRACTION  = 1 << 1
} plugin_caps_t;

/*!
    \brief A handle to a loaded plugin dynamic library.
    Pointers to this struct must be obtained through the plugin_load()
    and released through plugin_unload().
*/
typedef struct plugin_handle_t
{
#ifdef _WIN32
    HINSTANCE handle; ///< Handle of the dynamic library
#else
    void* handle; ///< Handle of the dynamic library
#endif
    plugin_api api; ///< The vtable method of the plugin that define its API
} plugin_handle_t;

/*!
    \brief Loads a dynamic library from the given path and returns a
    plugin_handle_t* representing the loaded plugin. In case of error,
    returns NULL and fills the err string up to PLUGIN_MAX_ERRLEN chars.
*/
plugin_handle_t* plugin_load(const char* path, char* err);

/*!
    \brief Destroys a plugin_handle_t* previously allocated by 
    invoking plugin_load().
*/
void plugin_unload(plugin_handle_t* h);

/*!
    \brief Returns true if the plugin at the given path is currently loaded.
*/
bool plugin_is_loaded(const char* path);

/*!
    \brief Returns true the API version required by the given plugin is
    compatible with the API version of the loader. Otherwise, returns false
    and fills the err string up to PLUGIN_MAX_ERRLEN chars.
*/
bool plugin_check_required_api_version(const plugin_handle_t* h, char* err);

/*!
    \brief Returns true if the given plugin handle implements all the
    minimum required function symbols for the current API version. Otherwise,
    returns false and fills the err string up to PLUGIN_MAX_ERRLEN chars.
*/
bool plugin_check_required_symbols(const plugin_handle_t* h, char* err);

/*!
    \brief Returns the capabilities supported by the given plugin handle
*/
plugin_caps_t plugin_get_capabilities(const plugin_handle_t* h);

#ifdef __cplusplus
}
#endif
