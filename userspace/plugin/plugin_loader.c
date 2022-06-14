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

#ifdef _WIN32
    typedef HINSTANCE library_handle_t;
#else
    #include <dlfcn.h>
    typedef void* library_handle_t;
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "plugin_loader.h"

static inline void add_str_prefix(char* s, const char* prefix)
{
    char tmp[PLUGIN_MAX_ERRLEN];
    strncpy(tmp, prefix, PLUGIN_MAX_ERRLEN - 1);
    strncat(tmp, s, PLUGIN_MAX_ERRLEN - 1);
    strcpy(s, tmp);
}

static void* getsym(library_handle_t handle, const char* name)
{
#ifdef _WIN32
	return (void*) GetProcAddress(handle, name);
#else
	return (void*) dlsym(handle, name);
#endif
}

// little hack for simplifying the plugin_load function
#define SYM_RESOLVE(h, s) \
    *(void **)(&(h->api.s)) = getsym(h->handle, "plugin_"#s)

plugin_handle_t* plugin_load(const char* path, char* err)
{
    // alloc and init memory
    plugin_handle_t* ret = (plugin_handle_t*) calloc (1, sizeof(plugin_handle_t));

    // open dynamic library
#ifdef _WIN32
    ret->handle = LoadLibrary(path);
    if(ret->handle == NULL)
    {
        DWORD flg = FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS;
        LPTSTR msg_buf = 0;
        if(FormatMessageA(flg, 0, GetLastError(), 0, (LPTSTR)&msg_buf, 0, NULL) && msg_buf)
        {
            errstr.append(msg_buf, strlen(msg_buf));
            strncpy(err, msg_buf, PLUGIN_MAX_ERRLEN -1 );
            LocalFree(msg_buf);
        }
    }
#else
    ret->handle = dlopen(path, RTLD_LAZY);
    if(ret->handle == NULL)
    {
        strncpy(err, (const char*) dlerror(), PLUGIN_MAX_ERRLEN - 1);
    }
#endif

    // return NULL if library loading had errors
    if (ret->handle == NULL)
    {
        add_str_prefix(err, "can't load plugin dynamic library: ");
        free(ret);
        return NULL;
    }

    // load all library symbols
    SYM_RESOLVE(ret, get_required_api_version);
    SYM_RESOLVE(ret, get_version);
    SYM_RESOLVE(ret, get_last_error);
    SYM_RESOLVE(ret, get_name);
    SYM_RESOLVE(ret, get_description);
    SYM_RESOLVE(ret, get_contact);
    SYM_RESOLVE(ret, get_init_schema);
    SYM_RESOLVE(ret, init);
    SYM_RESOLVE(ret, destroy);
    SYM_RESOLVE(ret, get_id);
    SYM_RESOLVE(ret, get_event_source);
    SYM_RESOLVE(ret, open);
    SYM_RESOLVE(ret, close);
    SYM_RESOLVE(ret, next_batch);
    SYM_RESOLVE(ret, get_progress);
    SYM_RESOLVE(ret, list_open_params);
    SYM_RESOLVE(ret, event_to_string);
    SYM_RESOLVE(ret, get_fields);
    SYM_RESOLVE(ret, extract_fields);
    SYM_RESOLVE(ret, get_extract_event_sources);
    return ret;
}

void plugin_unload(plugin_handle_t* h)
{
    if (h)
    {
        if (h->handle)
        {
#ifdef _WIN32
            FreeLibrary(h->handle);
#else
            dlclose(h->handle);
#endif
        }
        free(h);
    }
}

bool plugin_is_loaded(const char* path)
{
#ifdef _WIN32
	/*
	 * LoadLibrary maps the module into the address space of the calling process, if necessary,
	 * and increments the modules reference count, if it is already mapped.
	 * GetModuleHandle, however, returns the handle to a mapped module
	 * without incrementing its reference count.
	 *
	 * This returns an HMODULE indeed, but they are the same thing
	 */
	return GetModuleHandle(path) != NULL;
#else
	/*
	 * RTLD_NOLOAD (since glibc 2.2)
	 *	Don't load the shared object. This can be used to test if
	 *	the object is already resident (dlopen() returns NULL if
	 *	it is not, or the object's handle if it is resident).
	 *	This does not increment dlobject reference count.
	 */
	return dlopen(path, RTLD_LAZY | RTLD_NOLOAD) != NULL;
#endif
}

bool plugin_check_required_api_version(const plugin_handle_t* h, char* err)
{
    uint32_t major, minor, patch;
    const char *ver, *failmsg;
    if (h->api.get_required_api_version == NULL)
    {
        strncpy(err, "plugin_get_required_api_version symbol not implemented", PLUGIN_MAX_ERRLEN - 1);
        return false;
    }

    ver = h->api.get_required_api_version();
    if (sscanf(ver, "%" PRIu32 ".%" PRIu32 ".%" PRIu32, &major, &minor, &patch) != 3)
    {
        snprintf(err, PLUGIN_MAX_ERRLEN - 1, "plugin provided an invalid required API version: '%s'", ver);
        return false;
    }

    failmsg = NULL;
    if(PLUGIN_API_VERSION_MAJOR != major)
    {
        failmsg = "major versions disagree";
    }
    else if(PLUGIN_API_VERSION_MINOR < minor)
    {
        failmsg = "framework's minor is less than the requested one";
    }
    else if(PLUGIN_API_VERSION_MINOR == minor && PLUGIN_API_VERSION_PATCH < patch)
    {
        failmsg = "framework's patch is less than the requested one";
    }

    if (failmsg != NULL)
    {
        snprintf(err, PLUGIN_MAX_ERRLEN - 1,
            "plugin required API version '%s' not compatible with the framework's API version '%s': %s",
            ver, PLUGIN_API_VERSION_STR, failmsg);
        return false;
    }

    return true;
}

plugin_caps_t plugin_get_capabilities(const plugin_handle_t* h)
{
    plugin_caps_t caps = CAP_NONE;

    if (h->api.get_id != NULL
        && h->api.get_event_source != NULL
        && h->api.open != NULL
        && h->api.close != NULL
        && h->api.next_batch != NULL)
    {
        caps = (plugin_caps_t)((uint32_t) caps | (uint32_t) CAP_SOURCING);
    }

    if (h->api.get_fields != NULL
        && h->api.extract_fields != NULL)
    {
        caps = (plugin_caps_t)((uint32_t) caps | (uint32_t) CAP_EXTRACTION);
    }

    return caps;
}

// little hack for simplifying the plugin_check_required_symbols function
#define SYM_REQCHECK(a, e, s) \
    do { \
        if(a->api.s == NULL) \
        { \
            snprintf(e, PLUGIN_MAX_ERRLEN - 1, "symbol not implemented: %s", #s); \
            return false; \
        } \
    } while(0)

bool plugin_check_required_symbols(const plugin_handle_t* h, char* err)
{
    SYM_REQCHECK(h, err, get_required_api_version);
    SYM_REQCHECK(h, err, get_version);
    SYM_REQCHECK(h, err, get_name);
    SYM_REQCHECK(h, err, get_description);
    SYM_REQCHECK(h, err, get_contact);
    SYM_REQCHECK(h, err, init);
    SYM_REQCHECK(h, err, destroy);
    return true;
}
