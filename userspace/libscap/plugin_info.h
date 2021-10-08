/*
Copyright (C) 2021 The Falco Authors.

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

#include <stdbool.h>
#include <inttypes.h>

//
// This file contains the prototype and type definitions of sinsp/scap plugins
//

//
// API versions of this plugin engine
//
#define PLUGIN_API_VERSION_MAJOR 0
#define PLUGIN_API_VERSION_MINOR 1
#define PLUGIN_API_VERSION_PATCH 0

//
// There are two plugin types: source plugins and extractor plugins.
//
// Source plugins implement a new sinsp/scap event source and have the
// ability to provide events to the event loop. Optionally, they can
// extract fields from events so they can be displayed/used in
// filters.
//
// Extractor plugins do not provide events, but have the ability to
// extract fields from events created by other plugins. A good example
// of an extractor plugin is a json extractor, which can extract
// information from any json payload, regardless of where the payloads
// come from.
//
typedef enum ss_plugin_type
{
	TYPE_SOURCE_PLUGIN = 1,
	TYPE_EXTRACTOR_PLUGIN = 2
}ss_plugin_type;

// The noncontinguous numbers are to maintain equality with underlying
// falcosecurity libs types.
typedef enum ss_plugin_field_type
{
	FTYPE_UINT64 = 8,
	FTYPE_STRING = 9
}ss_plugin_field_type;

// Values to return from init() / open() / next() / next_batch() /
// extract_fields(). Note that these values map exactly to the
// corresponding SCAP_XXX values in scap.h, and should be kept in
// sync.
#define SS_PLUGIN_SUCCESS 0
#define SS_PLUGIN_FAILURE 1
#define SS_PLUGIN_TIMEOUT -1
#define SS_PLUGIN_ILLEGAL_INPUT 3
#define SS_PLUGIN_NOTFOUND 4
#define SS_PLUGIN_INPUT_TOO_SMALL 5
#define SS_PLUGIN_EOF 6
#define SS_PLUGIN_UNEXPECTED_BLOCK 7
#define SS_PLUGIN_VERSION_MISMATCH 8
#define SS_PLUGIN_NOT_SUPPORTED 9


// This struct represents an event returned by the plugin, and is used
// below in next()/next_batch().
// - evtnum: incremented for each event returned. Might not be contiguous.
// - data: pointer to a memory buffer pointer. The plugin will set it
//   to point to the memory containing the next event. Once returned,
//   the memory is owned by the plugin framework and will be freed via
//   a call to plugin_free_mem().
// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
//   buffer pointed by data.
// - ts: the event timestamp, in nanoseconds since the epoch.
//   Can be (uint64_t)-1, in which case the engine will automatically
//   fill the event time with the current time.
//
// Note: event numbers are assigned by the plugin
// framework. Therefore, there isn't any need to fill in evtnum when
// returning an event via plugin_next/plugin_next_batch. It will be ignored.
typedef struct ss_plugin_event
{
	uint64_t evtnum;
	uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

// Used in extract_fields functions below to receive a field/arg
// pair and return an extracted value.
// field: the field name.
// arg: the field argument, if an argument has been specified
//      for the field, otherwise it's NULL.
//      For example:
//         * if the field specified by the user is foo.bar[pippo], arg will be the
//           string "pippo"
//         * if the field specified by the user is foo.bar, arg will be NULL
// ftype: the type of the field. Could be derived from the field name alone,
//   but including here can prevent a second lookup of field names.
// The following should be filled in by the extraction function:
// - field_present: set to true if the event has a meaningful
//   extracted value for the provided field, false otherwise
// - res_str: if the corresponding field was type==string, this should be
//   filled in with the string value. The string should be allocated by
//   the plugin using malloc()/similar and will be free()d by the plugin
//   framework by calling plugin_free_mem().
// - res_u64: if the corresponding field was type==uint64, this should be
//   filled in with the uint64 value.

typedef struct ss_plugin_extract_field
{
	const char *field;
	const char *arg;
	uint32_t ftype;

	bool field_present;
	char *res_str;
	uint64_t res_u64;
} ss_plugin_extract_field;

//
// This is the opaque pointer to the state of a plugin.
// It points to any data that might be needed plugin-wise. It is
// allocated by init() and must be destroyed by destroy().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_plugin_t;

//
// This is the opaque pointer to the state of an open instance of the source
// plugin.
// It points to any data that is needed while a capture is running. It is
// allocated by open() and must be destroyed by close().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_instance_t;

//
// The structs below define the functions and arguments for source and
// exctractor plugins. The structs are used by the plugin framework to
// load and interface with plugins.
//
// From the perspective of the plugin, each function below should be
// exported from the dynamic library as a C calling convention
// function, adding a prefix "plugin_" to the function name
// (e.g. plugin_get_required_api_version, plugin_init, etc.)
//
// NOTE: For all functions below that return a char */struct *, the memory
// pointed to by the char */struct * must be allocated by the plugin using
// malloc()/similar and should be freed by the caller using plugin_free_mem().
//

//
// Interface for a sinsp/scap source plugin.
//
typedef struct
{
	//
	// Return the version of the plugin API used by this plugin.
	// Required: yes
	// Return value: the API version string, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// NOTE: to ensure correct interoperability between the engine and the plugins,
	//       we use a semver approach. Plugins are required to specify the version
	//       of the API they run against, and the engine will take care of checking
	//       and enforcing compatibility.
	//
	char* (*get_required_api_version)();
	//
	// The plugin framework will call this function to free any
	// memory allocated by the plugin and returned to the
	// framework. This includes return values from get_type()/get_name()/...,
	// get_last_error(), event structs returned in next_batch(), etc.
	void (*free_mem)(void *ptr);
	//
	// Return the plugin type.
	// Required: yes
	// Should return TYPE_SOURCE_PLUGIN. It still makes sense to
	// have a function get_type() as the plugin interface will
	// often dlsym() functions from shared libraries, and can't
	// inspect any C struct type.
	//
	uint32_t (*get_type)();
	//
	// Initialize the plugin and, if needed, allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to an integer that will contain the initialization result,
	//   as a SS_PLUGIN_* value (e.g. SS_PLUGIN_SUCCESS=0, SS_PLUGIN_FAILURE=1)
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the engine and passed to the other plugin functions.
	//   If rc is SS_PLUGIN_FAILURE, this function should return NULL.
	//
	ss_plugin_t* (*init)(char* config, int32_t* rc);
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// Required: yes
	//
	void (*destroy)(ss_plugin_t* s);
	//
	// Return a string with the error that was last generated by
	// the plugin.
	// Required: yes
	//
	// In cases where any other api function returns an error, the
	// plugin should be prepared to return a human-readable error
	// string with more context for the error. The plugin manager
	// calls get_last_error() to access that string.
	//
	char* (*get_last_error)(ss_plugin_t* s);
	//
	// Return the unique ID of the plugin.
	// Required: yes
	// EVERY SOURCE PLUGIN (see get_type()) MUST OBTAIN AN OFFICIAL ID FROM THE
	// FALCOSECURITY ORGANIZATION, OTHERWISE IT WON'T PROPERLY COEXIST WITH OTHER PLUGINS.
	//
	uint32_t (*get_id)();
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// Required: yes
	//
	char* (*get_description)();
	//
	// Return a string containing contact info (url, email, twitter, etc) for
	// the plugin authors.
	// Required: yes
	//
	char* (*get_contact)();
	//
	// Return the version of this plugin itself
	// Required: yes
	// Return value: a string with a version identifier, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// This differs from the api version in that this versions the
	// plugin itself, as compared to the plugin interface. When
	// reading capture files, the major version of the plugin that
	// generated events must match the major version of the plugin
	// used to read events.
	//
	char* (*get_version)();
	//
	// Return a string describing the events generated by this source plugin.
	// Required: yes
	// Example event sources would be strings like "syscall",
	// "k8s_audit", etc.  The source can be used by extractor
	// plugins to filter the events they receive.
	//
	char* (*get_event_source)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in Falco rule conditions and sysdig filters.
	// Required: no
	// Return value: a string with the list of fields encoded as a json
	//   array.
	//   Each field entry is a json object with the following properties:
	//     "type": one of "string", "uint64"
	//     "name": a string with a name for the field
	//     "argRequired: (optional) If present and set to true, notes
	//                   that the field requires an argument e.g. field[arg].
	//     "display": (optional) If present, a string that will be used to
	//                display the field instead of the name. Used in tools
	//                like wireshark.
	//     "desc": a string with a description of the field
	// Example return value:
	// [
	//    {"type": "string", "name": "field1", "argRequired": true, "desc": "Describing field 1"},
	//    {"type": "uint64", "name": "field2", "desc": "Describing field 2"}
	// ]
	char* (*get_fields)();
	//
	// Open the source and start a capture (e.g. stream of events)
	// Required: yes
	// Arguments:
	// - s: the plugin state returned by init()
	// - params: the open parameters, as a string. The format is defined by the plugin
	//   itsef
	// - rc: pointer to an integer that will contain the open result, as a SS_PLUGIN_* value
	//   (e.g. SS_PLUGIN_SUCCESS=0, SS_PLUGIN_FAILURE=1)
	// Return value: a pointer to the open context that will be passed to next(),
	//   close(), event_to_string() and extract_fields.
	//
	ss_instance_t* (*open)(ss_plugin_t* s, char* params, int32_t* rc);
	//
	// Close a capture.
	// Required: yes
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	//
	void (*close)(ss_plugin_t* s, ss_instance_t* h);
	//
	// Return the next event.
	// Required: yes
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	//
	// - evt: pointer to a ss_plugin_event pointer. The plugin should
	//   allocate a ss_plugin_event struct using malloc(), as well as
	//   allocate the data buffer within the ss_plugin_event struct.
	//   Both the struct and data buffer are owned by the plugin framework
	//   and will free them using plugin_free_mem().
	//
	// Return value: the status of the operation (e.g. SS_PLUGIN_SUCCESS=0, SS_PLUGIN_FAILURE=1,
	//   SS_PLUGIN_TIMEOUT=-1)
	//
	int32_t (*next)(ss_plugin_t* s, ss_instance_t* h, ss_plugin_event **evt);
	//
	// Return the read progress.
	// Required: no
	// Arguments:
	// - progress_pct: the read progress, as a number between 0 (no data has been read)
	//   and 10000 (100% of the data has been read). This encoding allows the engine to
	//   print progress decimals without requiring to deal with floating point numbers
	//   (which could cause incompatibility problems with some languages).
	// Return value: a string representation of the read
	//   progress. This might include the progress percentage
	//   combined with additional context added by the plugin. If
	//   NULL, progress_pct should be used.
	// NOTE: reporting progress is optional and in some case could be impossible. However,
	//       when possible, it's recommended as it provides valuable information to the
	//       user.
	//
	char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct);
	//
	// Return a text representation of an event generated by this source plugin.
	// Required: yes
	// Arguments:
	// - data: the buffer from an event produced by next().
	// - datalen: the length of the buffer from an event produced by next().
	// Return value: the text representation of the event. This is used, for example,
	//   by sysdig to print a line for the given event.
	//
	char *(*event_to_string)(ss_plugin_t *s, const uint8_t *data, uint32_t datalen);
	//
	// Extract one or more a filter field values from an event.
	// Required: no
	// Arguments:
	// - evt: an event struct returned by a call to next()/batch_next().
	// - num_fields: the length of the fields array.
	// - fields: an array of ss_plugin_extract_field structs. Each element contains
	//   a single field + optional arg, and the corresponding extracted value should
	//   be in the same struct.
	// Return value: An integer with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
	//
	int32_t (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);
	//
	// This is an optional, internal, function used to speed up event capture by
	// batching the calls to next().
	// On success:
	//   - nevts will be filled in with the number of events.
	//   - evts: pointer to an ss_plugin_event pointer. The plugin should
	//     allocate an array of contiguous ss_plugin_event structs using malloc(),
	//     as well as allocate each data buffer within each ss_plugin_event
	//     struct using malloc(). Both the array of structs and each data buffer are
	//     owned by the plugin framework and will free them using plugin_free_mem().
	// Required: no
	//
	int32_t (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);

	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	ss_plugin_t* state;
	ss_instance_t* handle;
	uint32_t id;
	char *name;
} source_plugin_info;

//
// Interface for a sinsp/scap extractor plugin
//
typedef struct
{
	//
	// Return the version of the plugin API used by this plugin.
	// Required: yes
	// Return value: the API version string, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// NOTE: to ensure correct interoperability between the engine and the plugins,
	//       we use a semver approach. Plugins are required to specify the version
	//       of the API they run against, and the engine will take care of checking
	//       and enforcing compatibility.
	//
	char* (*get_required_api_version)();
	//
	// The plugin framework will call this function to free any
	// memory allocated by the plugin and returned to the
	// framework. This includes return values from get_type()/get_name()/...,
	// get_last_error(), strings in extract_fields(), etc.
	void (*free_mem)(void *ptr);
	//
	// Return the plugin type.
	// Required: yes
	// Should return TYPE_EXTRACTOR_PLUGIN. It still makes sense to
	// have a function get_type() as the plugin interface will
	// often dlsym() functions from shared libraries, and can't
	// inspect any C struct type.
	//
	uint32_t (*get_type)();
	//
	// Initialize the plugin and, if needed, allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to an integer that will contain the initialization result,
	//   as a SS_PLUGIN_* value (e.g. SS_PLUGIN_SUCCESS=0, SS_PLUGIN_FAILURE=1)
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the engine and passed to the other plugin functions.
	//
	ss_plugin_t* (*init)(char* config, int32_t* rc);
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// Required: yes
	//
	void (*destroy)(ss_plugin_t* s);
	//
	// Return a string with the error that was last generated by
	// the plugin.
	// Required: yes
	//
	// In cases where any other api function returns an error, the
	// plugin should be prepared to return a human-readable error
	// string with more context for the error. The plugin manager
	// calls get_last_error() to access that string.
	//
	char* (*get_last_error)(ss_plugin_t* s);
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// Required: yes
	//
	char* (*get_description)();
	//
	// Return a string containing contact info (url, email, twitter, etc) for
	// the plugin author.
	// Required: yes
	//
	char* (*get_contact)();
	//
	// Return the version of this plugin itself
	// Required: yes
	// Return value: a string with a version identifier, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// This differs from the api version in that this versions the
	// plugin itself, as compared to the plugin interface. When
	// reading capture files, the major version of the plugin that
	// generated events must match the major version of the plugin
	// used to read events.
	//
	char* (*get_version)();
	//
	// Return a string describing the event sources that this
	// extractor plugin can consume.
	// Required: no
	// Return value: a json array of strings containing event
	//   sources returned by a source plugin's get_event_source()
	//   function.
	// This function is optional--if NULL then the exctractor
	// plugin will receive every event.
	//
	char* (*get_extract_event_sources)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in Falco rules and sysdig filters.
	// Required: yes
	// Return value: a string with the list of fields encoded as a json
	//   array.
	//
	char* (*get_fields)();

	//
	// Extract one or more a filter field values from an event.
	// Required: no
	// Arguments:
	// - evt: an event struct returned by a call to next()/batch_next().
	// - num_fields: the length of the fields array.
	// - fields: an array of ss_plugin_extract_field structs. Each element contains
	//   a single field + optional arg, and the corresponding extracted value should
	//   be in the same struct.
	// Return value: An integer with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
	//
	int32_t (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);

	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	ss_plugin_t* state;
} extractor_plugin_info;
