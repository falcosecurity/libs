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
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0
#define PLUGIN_API_VERSION_PATCH 0

//
// Just some not so smart defines to retrieve plugin api version as string
//
#define QUOTE(str) 			#str
#define EXPAND_AND_QUOTE(str) 		QUOTE(str)
#define PLUGIN_API_VERSION		PLUGIN_API_VERSION_MAJOR.PLUGIN_API_VERSION_MINOR.PLUGIN_API_VERSION_PATCH
#define PLUGIN_API_VERSION_STR		EXPAND_AND_QUOTE(PLUGIN_API_VERSION)

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

// Values to return from init() / open() / next_batch() /
// extract_fields().
typedef enum ss_plugin_rc
{
	SS_PLUGIN_SUCCESS = 0,
	SS_PLUGIN_FAILURE = 1,
	SS_PLUGIN_TIMEOUT = -1,
	SS_PLUGIN_EOF = 2,
	SS_PLUGIN_NOT_SUPPORTED = 3,
} ss_plugin_rc;

// The supported schema formats for the init configuration.
typedef enum ss_plugin_schema_type
{
	// The schema is undefined and the init configuration
	// is an opaque string.
	SS_PLUGIN_SCHEMA_NONE = 0,
	//
	// The schema follows the JSON Schema specific, and the
	// init configuration must be represented as a json.
	// see: https://json-schema.org/
	SS_PLUGIN_SCHEMA_JSON = 1,
} ss_plugin_schema_type;

// This struct represents an event returned by the plugin, and is used
// below in next_batch().
// - evtnum: incremented for each event returned. Might not be contiguous.
// - data: pointer to a memory buffer pointer. The plugin will set it
//   to point to the memory containing the next event.
// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
//   buffer pointed by data.
// - ts: the event timestamp, in nanoseconds since the epoch.
//   Can be (uint64_t)-1, in which case the engine will automatically
//   fill the event time with the current time.
//
// Note: event numbers are assigned by the plugin
// framework. Therefore, there isn't any need to fill in evtnum when
// returning an event via plugin_next_batch. It will be ignored.
typedef struct ss_plugin_event
{
	uint64_t evtnum;
	const uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

// Used in extract_fields functions below to receive a field/arg
// pair and return an extracted value.
// field_id: id of the field, as of its index in the list of
//           fields specified by the plugin.
// field: the field name.
// arg_key: the field argument, if a 'key' argument has been specified
//          for the field (isKey=true), otherwise it's NULL.
//          For example:
//          * if the field specified by the user is foo.bar[pippo], arg_key 
//            will be the string "pippo"
//         	* if the field specified by the user is foo.bar, arg will be NULL
// arg_index: the field argument, if a 'index' argument has been specified
//            for the field (isIndex=true), otherwise it's 0.
//            For example:
//            * if the field specified by the user is foo.bar[1], arg_index 
//            will be the uint64_t '1'. 
//            Please note the ambiguity with a 0
//            argument which could be a real argument of just the default 
//            value to point out the absence. The `arg_present` field resolves
//            this ambiguity.
// arg_present: helps to understand if the arg is there since arg_index is
//              0-based.
// ftype: the type of the field. Could be derived from the field name alone,
//   but including here can prevent a second lookup of field names.
// flist: whether the field can extract lists of values or not.
//   Could be derived from the field name alone, but including it
//   here can prevent a second lookup of field names.
// The following should be filled in by the extraction function:
// - res: this union should be filled with a pointer to an array of values.
//   The array represent the list of extracted values for this field from a given event.
//   Each array element should be filled with a char* string if the corresponding
//   field was type==string, and with a uint64 value if the corresponding field was
//   type==uint64.
// - res_len: the length of the array of pointed by res.
//   If the field is not a list type, then res_len must be either 0 or 1.
//   If the field is a list type, then res_len can must be any value from 0 to N, depending
//   on how many values can be extracted from a given event.
//   Setting res_len to 0 means that no value of this field can be extracted from a given event.


typedef struct ss_plugin_extract_field
{
	// NOTE: For a given architecture, this has always the same size which
	// is sizeof(uintptr_t). Adding new value types will not create breaking
	// changes in the plugin API. However, we must make sure that each added
	// type is always a pointer.
	union {
		const char** str;
		uint64_t* u64;
	} res;
	uint64_t res_len;

	// NOTE: When/if adding new input fields, make sure of appending them
	// at the end of the struct to avoid introducing breaking changes in the
	// plugin API.
	uint32_t field_id;
	const char* field;
	const char* arg_key;
	uint64_t arg_index;
	bool arg_present;
	uint32_t ftype;
	bool flist;
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
// extractor plugins. The structs are used by the plugin framework to
// load and interface with plugins.
//
// From the perspective of the plugin, each function below should be
// exported from the dynamic library as a C calling convention
// function, adding a prefix "plugin_" to the function name
// (e.g. plugin_get_required_api_version, plugin_init, etc.)
//
// Plugins are totally responsible of both allocating and deallocating memory.
// Plugins have the guarantee that they can safely deallocate memory in
// these cases:
// - During close(), for all the memory allocated in the context of a plugin
//   instance after open().
// - During destroy(), for all the memory allocated by the plugin, as it stops
//   being executed.
// - During subsequent calls to the same function, for all the exported
//   functions returning memory pointers.
//
// Plugins must not free memory passed in by the framework (i.e. function input
// parameters) if not corresponding to plugin-allocated memory in the
// cases above. Plugins can safely use the passed memory during the execution
// of the exported functions.

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
	const char* (*get_required_api_version)();
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
	// Return a string representation of a schema describing the data expected
	// to be passed as a configuration during the plugin initialization.
	// Required: no
	// Arguments:
	// - schema_type: The schema format type of the returned value among the
	//   list of the supported ones according to the ss_plugin_config_schema
	//   enumeration.
	// Return value: a string representation of the schema for the config
	//   to be passed to init().
	//
	// Plugins can optionally export this symbol to specify the expected
	// format for the configuration string passed to init(). If specified, 
	// the init() function can assume the config string to always be
	// well-formed. The framework will take care of automatically parsing it
	// against the provided schema and generating ad-hoc errors accordingly.
	// This also serves as a piece of documentation for users about how the
	// plugin needs to be configured.
	//
	const char* (*get_init_schema)(ss_plugin_schema_type* schema_type);
	//
	// Initialize the plugin and, if needed, allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to a ss_plugin_rc that will contain the initialization result
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the engine and passed to the other plugin functions.
	//   If rc is SS_PLUGIN_FAILURE, this function should return NULL.
	//
	ss_plugin_t* (*init)(const char* config, ss_plugin_rc* rc);
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
	const char* (*get_last_error)(ss_plugin_t* s);
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
	const char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// Required: yes
	//
	const char* (*get_description)();
	//
	// Return a string containing contact info (url, email, twitter, etc) for
	// the plugin authors.
	// Required: yes
	//
	const char* (*get_contact)();
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
	const char* (*get_version)();
	//
	// Return a string describing the events generated by this source plugin.
	// Required: yes
	// Example event sources would be strings like "syscall",
	// "k8s_audit", etc. The source can be used by extractor
	// plugins to filter the events they receive.
	//
	const char* (*get_event_source)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in Falco rule conditions.
	// Required: no
	// Return value: a string with the list of fields encoded as a json
	//   array.
	//   Each field entry is a json object with the following properties:
	//     "name": a string with a name for the field
	//     "type": one of "string", "uint64"
	//     "isList: (optional) If present and set to true, notes
	//              that the field extracts a list of values.
	//     "argRequired": [DEPRECATED, use "arg" property instead] 
	//                   (optional) If present and set to true, notes
	//                   that the field requires an argument e.g. field[arg].
	//     "arg": (optional) if present, notes that the field can accept
	//             an argument e.g. field[arg]. More precisely, the following
	//             flags could be specified:
	//             "isRequired": if true, the argument is required.
	//             "isIndex": if true, the field is numeric. 
	//             "isKey": if true, the field is a string.
	//             If "isRequired" is true, one between "isIndex" and
	//             "isKey" must be true, to specify the argument type.
	//             If "isRequired" is false, but one between "isIndex"
	//             and "isKey" is true, the argument is allowed but
	//             not required.
	//     "display": (optional) If present, a string that will be used to
	//                display the field instead of the name. Used in tools
	//                like wireshark.
	//     "desc": a string with a description of the field
	// Example return value:
	// [
	//    {"type": "string", "name": "field1", "argRequired": true, "desc": "Describing field 1"}, [DEPRECATED 'argRequired' property]
	//    {"type": "uint64", "name": "field2", "desc": "Describing field 2"},
	//    {"type": "string", "name": "field3", "arg": {"isRequired": true, "isIndex": true,}, "desc": "Describing field 3"},
	// ]
	const char* (*get_fields)();
	//
	// Open the source and start a capture (e.g. stream of events)
	// Required: yes
	// Arguments:
	// - s: the plugin state returned by init()
	// - params: the open parameters, as a string. The format is defined by the plugin
	//   itsef
	// - rc: pointer to a ss_plugin_rc that will contain the open result
	// Return value: a pointer to the open context that will be passed to next_batch(),
	//   close(), event_to_string() and extract_fields.
	//
	ss_instance_t* (*open)(ss_plugin_t* s, const char* params, ss_plugin_rc* rc);
	//
	// Close a capture.
	// Required: yes
	// Arguments:
	// - s: the plugin context, returned by init(). Can be NULL.
	// - h: the capture context, returned by open(). Can be NULL.
	//
	void (*close)(ss_plugin_t* s, ss_instance_t* h);
	//
	// Return a list of suggested open parameters supported by this plugin.
	// Any of the values in the returned list are valid parameters for open().
	// Required: no
	// Return value: a string with the list of open params encoded as
	//   a json array.
	//   Each field entry is a json object with the following properties:
	//     "value": a string usable as an open() parameter.
	//     "desc": (optional) a string with a description of the parameter.
	//   Example return value:
	//   [
	//      {"value": "resource1", "desc": "An example of openable resource"},
	//      {"value": "resource2", "desc": "Another example of openable resource"}
	//   ]
	const char* (*list_open_params)(ss_plugin_t* s, ss_plugin_rc* rc);
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
    //   The returned memory pointer must be allocated by the plugin
	//   and must not be deallocated or modified until the next call to
	//   get_progress().
	// NOTE: reporting progress is optional and in some case could be impossible. However,
	//       when possible, it's recommended as it provides valuable information to the
	//       user.
	//
	const char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct);
	//
	// Return a text representation of an event generated by this source plugin.
	// Required: yes
	// Arguments:
	// - data: the buffer from an event produced by next_batch().
	// - datalen: the length of the buffer from an event produced by next_batch().
	// Return value: the text representation of the event. This is used, for example,
	//   to print a line for the given event.
	//   The returned memory pointer must be allocated by the plugin
	//   and must not be deallocated or modified until the next call to
	//   event_to_string().
	//
	const char* (*event_to_string)(ss_plugin_t *s, const uint8_t *data, uint32_t datalen);
	//
	// Extract one or more a filter field values from an event.
	// Required: no
	// Arguments:
	// - evt: an event struct produced by a call to next_batch().
	//   This is allocated by the framework, and it is not guaranteed
	//   that the event struct pointer is the same returned by the last
	//   next_batch() call.
	// - num_fields: the length of the fields array.
	// - fields: an array of ss_plugin_extract_field structs. Each entry
	//   contains a single field + optional argument as input, and the corresponding
	//   extracted value as output. Memory pointers set as output must be allocated
	//   by the plugin and must not be deallocated or modified until the next
	//   extract_fields() call.
	//
	// Return value: A ss_plugin_rc with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
	//
	ss_plugin_rc (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);
	//
	// Return the next batch of events.
	// On success:
	//   - nevts will be filled in with the number of events.
	//   - evts: pointer to an ss_plugin_event pointer. The plugin must
	//     allocate an array of contiguous ss_plugin_event structs
	//     and each data buffer within each ss_plugin_event struct.
	//     Memory pointers set as output must be allocated by the plugin
	//     and must not be deallocated or modified until the next call to
	//     next_batch() or close().
	// Required: yes
	//
	ss_plugin_rc (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);
	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	ss_plugin_t* state;
	ss_instance_t* handle;
	uint32_t id;
	const char* name;
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
	const char* (*get_required_api_version)();
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
	// Return a string representation of a schema describing the data expected
	// to be passed as a configuration during the plugin initialization.
	// Required: no
	// Arguments:
	// - schema_type: The schema format type of the returned value among the
	//   list of the supported ones according to the ss_plugin_config_schema
	//   enumeration.
	// Return value: a string representation of the schema for the config
	//   to be passed to init().
	//
	// Plugins can optionally export this symbol to specify the expected
	// format for the configuration string passed to init(). If specified, 
	// the init() function can assume the config string to always be
	// well-formed. The framework will take care of automatically parsing it
	// against the provided schema and generating ad-hoc errors accordingly.
	// This also serves as a piece of documentation for users about how the
	// plugin needs to be configured.
	//
	const char* (*get_init_schema)(ss_plugin_schema_type* schema_type);
	//
	// Initialize the plugin and, if needed, allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to a ss_plugin_rc that will contain the initialization result
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the engine and passed to the other plugin functions.
	//
	ss_plugin_t* (*init)(const char* config, ss_plugin_rc* rc);
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
	const char* (*get_last_error)(ss_plugin_t* s);
	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	const char* (*get_name)();
	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin or its events.
	// Required: yes
	//
	const char* (*get_description)();
	//
	// Return a string containing contact info (url, email, twitter, etc) for
	// the plugin author.
	// Required: yes
	//
	const char* (*get_contact)();
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
	const char* (*get_version)();
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
	const char* (*get_extract_event_sources)();
	//
	// Return the list of extractor fields exported by this plugin. Extractor
	// fields can be used in Falco rules.
	// Required: yes
	// Return value: a string with the list of fields encoded as a json
	//   array.
	//
	const char* (*get_fields)();
	//
	// Extract one or more a filter field values from an event.
	// Required: yes
	// Arguments:
	// - evt: an event struct provided by the framework.
	// - num_fields: the length of the fields array.
	// - fields: an array of ss_plugin_extract_field structs. Each entry
	//   contains a single field + optional argument as input, and the corresponding
	//   extracted value as output. Memory pointers set as output must be allocated
	//   by the plugin and must not be deallocated or modified until the next
	//   extract_fields() call.
	//
	// Return value: A ss_plugin_rc with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
	//
	ss_plugin_rc (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);
	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	ss_plugin_t* state;
} extractor_plugin_info;
