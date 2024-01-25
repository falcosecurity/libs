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

#include <plugin/plugin_types.h>

#ifdef __cplusplus
extern "C" {
#endif


//
// API versions of this plugin framework
//
// todo(jasondellaluce): when/if major changes to v4, check and solve all todos
#define PLUGIN_API_VERSION_MAJOR 3
#define PLUGIN_API_VERSION_MINOR 3
#define PLUGIN_API_VERSION_PATCH 0

//
// Just some not so smart defines to retrieve plugin api version as string
//
#define QUOTE(str)                  #str
#define EXPAND_AND_QUOTE(str)       QUOTE(str)
#define PLUGIN_API_VERSION          PLUGIN_API_VERSION_MAJOR.PLUGIN_API_VERSION_MINOR.PLUGIN_API_VERSION_PATCH
#define PLUGIN_API_VERSION_STR      EXPAND_AND_QUOTE(PLUGIN_API_VERSION)

//
// The max length of errors returned by a plugin in some of its API symbols.
//
#define PLUGIN_MAX_ERRLEN	1024

// Supported by the API but deprecated. Use the extended version ss_plugin_table_reader_vtable_ext instead.
// todo(jasondellaluce): when/if major changes to v4, remove this and
// give this name to the associated *_ext struct.
typedef struct
{
	ss_plugin_table_fieldinfo* (*list_table_fields)(ss_plugin_table_t* t, uint32_t* nfields);
	ss_plugin_table_field_t* (*get_table_field)(ss_plugin_table_t* t, const char* name, ss_plugin_state_type data_type);
	ss_plugin_table_field_t* (*add_table_field)(ss_plugin_table_t* t, const char* name, ss_plugin_state_type data_type);
} ss_plugin_table_fields_vtable;

// Vtable for controlling and the fields for the entries of a state table.
// This allows discovering the fields available in the table, defining new ones,
// and obtaining accessors usable at runtime for reading and writing the fields'
// data from each entry of a given state table.
typedef struct
{
	// Returns a pointer to an array containing info about all the fields
	// available in the entries of the table. nfields will be filled with the number
	// of elements of the returned array. The array's memory is owned by the
	// tables's owner. Returns NULL in case of error.
	ss_plugin_table_fieldinfo* (*list_table_fields)(ss_plugin_table_t* t, uint32_t* nfields);
	//
	// Returns an opaque pointer representing an accessor to a data field
	// present in all entries of the table, given its name and type.
	// This can later be used for read and write operations for all entries of
	// the table. The pointer is owned by the table's owner.
	// Returns NULL in case of issues (including when the field is not defined
	// or it has a type different than the specified one).
	ss_plugin_table_field_t* (*get_table_field)(ss_plugin_table_t* t, const char* name, ss_plugin_state_type data_type);
	//
	// Defines a new field in the table given its name and data type,
	// which will then be available in all entries contained in the table.
	// Returns an opaque pointer representing an accessor to the newly-defined
	// field. This can later be used for read and write operations for all entries of
	// the table. The pointer is owned by the table's owner.
	// Returns NULL in case of issues (including when a field is defined multiple
	// times with different data types).
	ss_plugin_table_field_t* (*add_table_field)(ss_plugin_table_t* t, const char* name, ss_plugin_state_type data_type);
} ss_plugin_table_fields_vtable_ext;

// Supported by the API but deprecated. Use the extended version ss_plugin_table_reader_vtable_ext instead.
// todo(jasondellaluce): when/if major changes to v4, remove this and
// give this name to the associated *_ext struct.
typedef struct
{
	const char*	(*get_table_name)(ss_plugin_table_t* t);
	uint64_t (*get_table_size)(ss_plugin_table_t* t);
	ss_plugin_table_entry_t* (*get_table_entry)(ss_plugin_table_t* t, const ss_plugin_state_data* key);
	ss_plugin_rc (*read_entry_field)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e, const ss_plugin_table_field_t* f, ss_plugin_state_data* out);
} ss_plugin_table_reader_vtable;

// Opaque pointer to the state data relative to a state table iteration.
// This is passed initially by the invoker when starting the iteration, and
// is then dispatched to the iterator for each of the entries of the table.
typedef void ss_plugin_table_iterator_state_t;

// Iterator function callback used by a plugin for looping through all the
// entries of a given state table. Returns true if the iteration should
// proceed to the next element, or false in case of break out.
typedef ss_plugin_bool (*ss_plugin_table_iterator_func_t)(ss_plugin_table_iterator_state_t* s, ss_plugin_table_entry_t* e);

typedef struct
{
	// Returns the table's name, or NULL in case of error.
	// The returned pointer is owned by the table's owner.
	const char*	(*get_table_name)(ss_plugin_table_t* t);
	//
	// Returns the number of entries in the table, or ((uint64_t) -1) in
	// case of error.
	uint64_t (*get_table_size)(ss_plugin_table_t* t);
	//
	// Returns an opaque pointer to an entry present in the table at the given
	// key, or NULL in case of issues (including if no entry is found at the
	// given key). The returned pointer is owned by the table's owner.
	// Every non-NULL returned entry must be released by invoking release_table_entry()
	// once it becomes no more used by the invoker.
	ss_plugin_table_entry_t* (*get_table_entry)(ss_plugin_table_t* t, const ss_plugin_state_data* key);
	//
	// Reads the value of an entry field from a table's entry.
	// The field accessor must be obtainied during plugin_init().
	// The read value is stored in the "out" parameter.
	// Returns SS_PLUGIN_SUCCESS if successful, and SS_PLUGIN_FAILURE otherwise.
	ss_plugin_rc (*read_entry_field)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e, const ss_plugin_table_field_t* f, ss_plugin_state_data* out);
	//
	// Releases a table entry obtained by from previous invocation of get_table_entry().
	// After being released, the same table entry cannot be reused by the invoker.
	// However, the same entry can be re-obtained through an invocation of get_table_entry().
	void (*release_table_entry)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e);
	//
	// Iterates through all the entries of a table, invoking the interation
	// callback function for each of them. Returns false in case of failure or
	// iteration break-out, and true otherwise.
	ss_plugin_bool (*iterate_entries)(ss_plugin_table_t* t, ss_plugin_table_iterator_func_t it, ss_plugin_table_iterator_state_t* s);
} ss_plugin_table_reader_vtable_ext;

// Supported by the API but deprecated. Use the extended version ss_plugin_table_writer_vtable_ext instead.
// todo(jasondellaluce): when/if major changes to v4, remove this and
// give this name to the associated *_ext struct.
typedef struct
{
	ss_plugin_rc (*clear_table)(ss_plugin_table_t* t);
	ss_plugin_rc (*erase_table_entry)(ss_plugin_table_t* t, const ss_plugin_state_data* key);
	ss_plugin_table_entry_t* (*create_table_entry)(ss_plugin_table_t* t);
	void (*destroy_table_entry)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e);
	ss_plugin_table_entry_t* (*add_table_entry)(ss_plugin_table_t* t, const ss_plugin_state_data* key, ss_plugin_table_entry_t* entry);
	ss_plugin_rc (*write_entry_field)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e, const ss_plugin_table_field_t* f, const ss_plugin_state_data* in);
} ss_plugin_table_writer_vtable;

// Vtable for controlling a state table for write operations.
typedef struct
{
	// Erases all the entries of the table.
	// Returns SS_PLUGIN_SUCCESS if successful, and SS_PLUGIN_FAILURE otherwise.
	ss_plugin_rc (*clear_table)(ss_plugin_table_t* t);
	//
	// Erases an entry from a table at the given key.
	// Returns SS_PLUGIN_SUCCESS if successful, and SS_PLUGIN_FAILURE otherwise.
	ss_plugin_rc (*erase_table_entry)(ss_plugin_table_t* t, const ss_plugin_state_data* key);
	//
	// Creates a new entry that can later be added to the same table it was
	// created from. The entry is represented as an opaque pointer owned
	// by the plugin. Once obtained, the plugin can either add the entry
	// to the table through add_table_entry(), or destroy it throgh
	// destroy_table_entry(). Returns an opaque pointer to the newly-created
	// entry, or NULL in case of error.
	ss_plugin_table_entry_t* (*create_table_entry)(ss_plugin_table_t* t);
	//
	// Destroys a table entry obtained by from previous invocation of create_table_entry().
	void (*destroy_table_entry)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e);
	//
	// Adds a new entry to a table obtained by from previous invocation of
	// create_table_entry() on the same table. The entry is inserted in the table
	// with the given key. If another entry is already present with the same key,
	// it gets replaced. After insertion, table will be come the owner of the
	// entry's pointer. Returns an opaque pointer to the newly-added table's entry,
	// or NULL in case of error. Every non-NULL returned entry must be released
	// by invoking release_table_entry() once it becomes no more used by the invoker.
	ss_plugin_table_entry_t* (*add_table_entry)(ss_plugin_table_t* t, const ss_plugin_state_data* key, ss_plugin_table_entry_t* entry);
	//
	// Updates a table's entry by writing a value for one of its fields.
	// The field accessor must be obtainied during plugin_init().
	// The written value is read from the "in" parameter.
	// Returns SS_PLUGIN_SUCCESS if successful, and SS_PLUGIN_FAILURE otherwise.
	ss_plugin_rc (*write_entry_field)(ss_plugin_table_t* t, ss_plugin_table_entry_t* e, const ss_plugin_table_field_t* f, const ss_plugin_state_data* in);
} ss_plugin_table_writer_vtable_ext;

// Plugin-provided input passed to the add_table() callback of
// ss_plugin_init_tables_input, that can be used by the plugin to inform its
// owner about one of the state tables owned by the plugin. The plugin
// is responsible of owning all the memory pointed by this struct and
// of implementing all the API functions. These will be used by other
// plugins loaded by the falcosecurity libraries to interact with the state
// of a given plugin to implement cross-plugin state access.
typedef struct
{
	// The name of the state table.
	const char* name;
	//
	// The type of the state table's key.
	ss_plugin_state_type key_type;
	//
	// A non-NULL opaque pointer to the state table.
	// This will be passed as parameters to all the callbacks defined below.
	ss_plugin_table_t* table;
	//
	// Supported but deprecated. Use the extended version reader_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_reader_vtable reader;
	//
	// Supported but deprecated. Use the extended version writer_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_writer_vtable writer;
	//
	// Supported but deprecated. Use the extended version fields_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_fields_vtable fields;
	//
	// Vtable for controlling read operations on the state table.
	ss_plugin_table_reader_vtable_ext* reader_ext;
	//
	// Vtable for controlling write operations on the state table.
	ss_plugin_table_writer_vtable_ext* writer_ext;
	//
	// Vtable for controlling operations related to fields on the state table.
	ss_plugin_table_fields_vtable_ext* fields_ext;
} ss_plugin_table_input;

// Initialization-time input related to the event parsing or field extraction capability.
// This provides the plugin with callback functions implemented by its owner
// that can be used to discover, access, and define state tables.
typedef struct
{
	// Returns a pointer to an array containing info about all the tables
	// registered in the plugin's owner. ntables will be filled with the number
	// of elements of the returned array. The array's memory is owned by the
	// plugin's owner. Returns NULL in case of error.
	ss_plugin_table_info* (*list_tables)(ss_plugin_owner_t* o, uint32_t* ntables);
	//
	// Returns an opaque accessor to a state table registered in the plugin's
	// owner, given its name and key type. Returns NULL if an case of error.
	ss_plugin_table_t* (*get_table)(ss_plugin_owner_t* o, const char* name, ss_plugin_state_type key_type);
	//
	// Registers a new state table in the plugin's owner. Returns
	// SS_PLUGIN_SUCCESS in case of success, and SS_PLUGIN_FAILURE otherwise.
	// The state table is owned by the plugin itself, and the input will be used
	// by other actors of the plugin's owner to interact with the state table.
	ss_plugin_rc (*add_table)(ss_plugin_owner_t* o, const ss_plugin_table_input* in);
	//
	// Supported but deprecated. Use the extended version fields_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_fields_vtable fields;
	//
	// Vtable for controlling operations related to fields on the state tables
	// registeted in the plugin's owner.
	ss_plugin_table_fields_vtable_ext* fields_ext;
} ss_plugin_init_tables_input;

// Function used by plugin for sending messages to the framework-provided logger
// Arguments:
//  - component: name of the component that is logging
//			(if set to NULL automatically falls back to the plugin name in the log)
//  - msg: message to log 
//			(it doesn't have to be '\n' terminated)
//  - sev: message severity as defined in ss_plugin_log_severity
typedef void (*ss_plugin_log_fn_t)(ss_plugin_owner_t* o, const char* component, const char* msg, ss_plugin_log_severity sev);

// Input passed at the plugin through plugin_init(). This contain information
// common to any plugin, and also information useful only in case the plugin
// implements a given capability. If a certain capability is not implemented
// by the plugin, its information is set to NULL.
typedef struct ss_plugin_init_input
{
	// An opaque string representing the plugin init configuration.
	// The format of the string is arbitrary and defined by the plugin itself.
	const char* config;
	//
	// The plugin's owner. Can be passed by the plugin to the callbacks available
	// in this struct in order to invoke functions of its owner.
	// It doesn't change during the whole plugin's lifecycle, it's safe to store it in the state
	ss_plugin_owner_t* owner;
	//
	// Return a string with the error that was last generated by the plugin's
	// owner, or NULL if no error is present.
	// The string pointer is owned by the plugin's owenr.
	const char *(*get_owner_last_error)(ss_plugin_owner_t *o);
	//
	// Init input related to the event parsing or field extraction capability.
	// It's set to NULL if the plugin does not implement at least one of the two
	// capabilities. The callbacks available in this input take the plugin's owner
	// as a parameter.
	const ss_plugin_init_tables_input* tables;
	//
	// Log function passed to the plugin through the init input
	// It doesn't change during the whole plugin's lifecycle, it's safe to store it in the state
	ss_plugin_log_fn_t log_fn;
} ss_plugin_init_input;

// Input passed to the plugin when extracting a field from an event for
// the field extraction capability.
typedef struct ss_plugin_field_extract_input
{
	//
	// The plugin's owner. Can be passed by the plugin to the callbacks available
	// in this struct in order to invoke functions of its owner.
	ss_plugin_owner_t* owner;
	//
	// Return a string with the error that was last generated by the plugin's
	// owner, or NULL if no error is present.
	// The string pointer is owned by the plugin's owenr.
	const char *(*get_owner_last_error)(ss_plugin_owner_t *o);
	//
	// The length of the fields array.
	uint32_t num_fields;
	//
	// An array of ss_plugin_extract_field structs. Each entry
	// contains a single field + optional argument as input, and the corresponding
	// extracted value as output. Memory pointers set as output must be allocated
	// by the plugin and must not be deallocated or modified until the next
	// extract_fields() call.
	ss_plugin_extract_field *fields;
	//
	// Supported but deprecated. Use the extended version table_reader_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_reader_vtable table_reader;
	//
	// Vtable for controlling a state table for read operations.
	ss_plugin_table_reader_vtable_ext* table_reader_ext;
} ss_plugin_field_extract_input;

// Input passed to the plugin when parsing an event for the event parsing
// capability.
typedef struct ss_plugin_event_parse_input
{
	//
	// The plugin's owner. Can be passed by the plugin to the callbacks available
	// in this struct in order to invoke functions of its owner.
	ss_plugin_owner_t* owner;
	//
	// Return a string with the error that was last generated by the plugin's
	// owner, or NULL if no error is present.
	// The string pointer is owned by the plugin's owenr.
	const char *(*get_owner_last_error)(ss_plugin_owner_t *o);
	//
	// Supported but deprecated. Use the extended version table_reader_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_reader_vtable table_reader;
	//
	// Supported but deprecated. Use the extended version table_writer_ext.
	// todo(jasondellaluce): when/if major changes to v4, remove this and
	// give this name to the associated *_ext pointer.
	ss_plugin_table_writer_vtable table_writer;
	//
	// Vtable for controlling a state table for read operations.
	ss_plugin_table_reader_vtable_ext* table_reader_ext;
	//
	// Vtable for controlling a state table for write operations.
	ss_plugin_table_writer_vtable_ext* table_writer_ext;
} ss_plugin_event_parse_input;

//
// Function handler used by plugin for sending asynchronous events to the
// Falcosecurity libs during a live event capture. The asynchronous events
// must be encoded as an async event type (code 402) as for the libscap specific.
//
// The plugin framework will automatically set the plugin ID of the produced
// async event depending on the running event source in which the event will
// be injected into. The event's thread ID can be set to control the system
// thread associated, with value (uint64_t) -1) representing no thread
// association. The event's timestamp can be set to forcefully specify
// the timestamp of the phenomena that the event represents, and value
// (uint64_t) -1) will cause the plugin framework to automatically assign
// a timestamp as the time in which the event is received asynchronously.
//
// The function returns SS_PLUGIN_SUCCESS in case of success, or
// SS_PLUGIN_FAILURE otherwise. If a non-NULL char pointer is passed for
// the "err" argument, it will be filled with an error message string
// in case the handler function returns SS_PLUGIN_FAILURE. The error string
// has a max length of PLUGIN_MAX_ERRLEN (termination char included) and its
// memory must be allocated and owned by the plugin.
typedef ss_plugin_rc (*ss_plugin_async_event_handler_t)(ss_plugin_owner_t* o, const ss_plugin_event *evt, char* err);

//
// The struct below define the functions and arguments for plugins capabilities:
// * event sourcing
// * field extraction
// * event parsing
// The structs are used by the plugin framework to load and interface with plugins.
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
// Plugins API vtable
//
typedef struct
{
	//
	// Return the version of the plugin API used by this plugin.
	// Required: yes
	// Return value: the API version string, in the following format:
	//       "<major>.<minor>.<patch>", e.g. "1.2.3".
	// NOTE: to ensure correct interoperability between the framework and the plugins,
	//       we use a semver approach. Plugins are required to specify the version
	//       of the API they run against, and the framework will take care of checking
	//       and enforcing compatibility.
	//
	const char *(*get_required_api_version)();

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
	const char *(*get_init_schema)(ss_plugin_schema_type *schema_type);

	//
	// Initialize the plugin and allocate its state.
	// Required: yes
	// Arguments:
	// - in: init-time input for the plugin.
	// - rc: pointer to a ss_plugin_rc that will contain the initialization result
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the framework and passed to the other plugin functions.
	//   If rc is SS_PLUGIN_FAILURE, this function may return NULL or a state to
	//   later retrieve the error string.
	// 
	// If a non-NULL ss_plugin_t* state is returned, then subsequent invocations
	// of init() must not return the same ss_plugin_t* value again, if not after
	// it has been disposed with destroy() first.
	ss_plugin_t *(*init)(const ss_plugin_init_input *input, ss_plugin_rc *rc);

	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// Required: yes
	//
	void (*destroy)(ss_plugin_t *s);

	//
	// Return a string with the error that was last generated by
	// the plugin.
	// Required: yes
	//
	// In cases where any other api function returns an error, the
	// plugin should be prepared to return a human-readable error
	// string with more context for the error. The framework
	// calls get_last_error() to access that string.
	//
	const char *(*get_last_error)(ss_plugin_t *s);

	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	const char *(*get_name)();

	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	const char *(*get_description)();

	//
	// Return a string containing contact info (url, email, etc) for
	// the plugin authors.
	// Required: yes
	//
	const char *(*get_contact)();

	//
	// Return the version of this plugin itself
	// Required: yes
	// Return value: a string with a version identifier, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// This differs from the api version in that this versions the
	// plugin itself. Note, increasing the major version signals breaking
	// changes in the plugin implementation but must not change the
	// serialization format of the event data. For example, events written
	// in pre-existing capture files must always be readable by newer versions
	// of the plugin.
	//
	const char *(*get_version)();

	// Event sourcing capability API
	struct
	{
		//
		// Return the unique ID of the plugin.
		// Required: yes if get_event_source is defined and returns a non-empty string, no otherwise.
		// 
		// If the plugin has a specific ID and event source, then its next_batch()
		// function is allowed to only return events of plugin type (code 322)
		// with its own plugin ID and event source.
		//
		// EVERY PLUGIN WITH EVENT SOURCING CAPABILITY IMPLEMENTING
		// A SPECIFIC EVENT SOURCE MUST OBTAIN AN OFFICIAL ID FROM THE
		// FALCOSECURITY ORGANIZATION, OTHERWISE IT WON'T PROPERLY COEXIST
		// WITH OTHER PLUGINS.
		//
		uint32_t (*get_id)();

		//
		// Return a string representing the name of the event source generated
		// by this plugin.
		// Required: yes if get_id is defined and returns a non-zero number, no otherwise.
		// 
		// If the plugin has a specific ID and event source, then its next_batch()
		// function is allowed to only return events of plugin type (code 322)
		// with its own plugin ID and event source.
		//
		// Example event sources would be strings like "aws_cloudtrail",
		// "k8s_audit", etc. The source can be used by plugins with event
		// sourcing capabilities to filter the events they receive.
		//
		const char* (*get_event_source)();

		//
		// Open the event source and start a capture (e.g. stream of events)
		// Required: yes
		// Arguments:
		// - s: the plugin state returned by init()
		// - params: the open parameters, as an opaque string.
		//           The string format is defined by the plugin itself
		// - rc: pointer to a ss_plugin_rc that will contain the open result
		// Return value: a pointer to the opened plugin instance that will be
		//               passed to next_batch(), close(), event_to_string()
		//               and extract_fields().
		//
		// If a non-NULL ss_instance_t* instance is returned, then subsequent
		// invocations of open() must not return the same ss_instance_t* value
		// again, if not after it has been disposed with close() first.
		ss_instance_t* (*open)(ss_plugin_t* s, const char* params, ss_plugin_rc* rc);

		//
		// Close a capture.
		// Required: yes
		// Arguments:
		// - s: the plugin state, returned by init(). Can be NULL.
		// - h: the plugin instance, returned by open(). Can be NULL.
		//
		void (*close)(ss_plugin_t* s, ss_instance_t* h);

		//
		// Return a list of suggested open parameters supported by this plugin.
		// Any of the values in the returned list are valid parameters for open().
		// Required: no
		// Return value: a string with the list of open params encoded as
		//   a json array. Each field entry is a json object with the following
		//   properties:
		//     - "value": a string usable as an open() parameter.
		//     - "desc": (optional) a string with a description of the parameter.
		//     - "separator": (optional) a separator string, for when "value"
		//                    represents multiple contatenated open parameters
		//   Example return value:
		//   [
		//      {"value": "resource1", "desc": "An example of openable resource"},
		//      {"value": "resource2", "desc": "Another example of openable resource"},
		//      {
		//          "value": "res1;res2;res3",
		//          "desc": "Some names",
		//          "separator": ";"
		//      }
		//   ]
		const char* (*list_open_params)(ss_plugin_t* s, ss_plugin_rc* rc);

		//
		// Return the read progress.
		// Required: no
		// Arguments:
		// - progress_pct: the read progress, as a number between 0 (no data has been read)
		//   and 10000 (100% of the data has been read). This encoding allows the framework to
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
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// If the returned pointer is non-NULL, then it must be uniquely
		// attached to the ss_instance_t* parameter value. The pointer must not
		// be shared across multiple distinct ss_instance_t* values.
		const char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct);

		//
		// Return a text representation of an event generated by this plugin with
		// event sourcing capability. Even if defined, this function is not
		// used by the framework if the plugin does not implement a specific
		// event source (get_id() is zero or get_event_source() is empty).
		// 
		// Required: no
		//
		// Arguments:
		// - evt: an event input provided by the framework.
		//   This is allocated by the framework, and it is not guaranteed
		//   that the event struct pointer is the same returned by the last
		//   next_batch() call.
		// Return value: the text representation of the event. This is used, for example,
		//   to print a line for the given event.
		//   The returned memory pointer must be allocated by the plugin
		//   and must not be deallocated or modified until the next call to
		//   event_to_string().
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// If the returned pointer is non-NULL, then it must be uniquely
		// attached to the ss_plugin_t* parameter value. The pointer must not
		// be shared across multiple distinct ss_plugin_t* values.
		const char* (*event_to_string)(ss_plugin_t *s, const ss_plugin_event_input *evt);

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
		// If a plugin implements a specific event source (get_id() is non-zero
		// and get_event_source() is non-empty), then, it is only allowed to
		// produce events of type plugin (code 322) containing its own plugin ID
		// (as returned by get_id()). In such a case, when an event contains
		// a zero plugin ID, the framework automatically sets the plugin ID of
		// the event to the one of the plugin. If a plugin does not implement
		// a specific event source, it is allowed to produce events of any
		// of the types supported by the libscap specific.
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// The value of the ss_plugin_event** output parameter must be uniquely
		// attached to the ss_instance_t* parameter value. The pointer must not
		// be shared across multiple distinct ss_instance_t* values.
		ss_plugin_rc (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event ***evts);
	};

	// Field extraction capability API
	struct
	{
		//
		// Return the list of event types that this plugin will receive
		// for field extraction. The event types follow the libscap specific.
		// This will be invoked only once by the framework after the plugin's
		// initialization. Events that are not included in the returned list
		// will not be received by the plugin.
		// 
		// This is a non-functional filter that should not influence the plugin's
		// functional behavior. Instead, this is a performance optimization
		// with the goal of avoiding unnecessary communication between the
		// framework and the plugin for events that are known to be not used for
		// field extraction. 
		// 
		// Required: no
		//
		// This function is optional--if NULL or an empty array, then:
		// - the plugin will receive every event type if the result of
		//   get_extract_event_sources (either default or custom) is compatible
		//   with the "syscall" event source, otherwise
		// - the plugin will only receive events of plugin type (code 322).
		// todo(jasondellaluce): when/if major changes to v4, reorder the arguments
		// and put ss_plugin_t* as first
		uint16_t* (*get_extract_event_types)(uint32_t* numtypes, ss_plugin_t* s);

		//
		// Return a string describing the event sources that this plugin
		// can consume for field extraction.
		// Required: no
		// Return value: a json array of strings containing event
		//   sources returned by a plugin with event sourcing capabilities get_event_source()
		//   function, or "syscall" for indicating support to non-plugin events.
		// This function is optional--if NULL or an empty array, then if plugin has sourcing capability,
		// and implements a specific event source, it will only receive events matching its event source,
		// otherwise it will receive events from all event sources.
		//
		const char* (*get_extract_event_sources)();

		//
		// Return the list of extractor fields exported by this plugin. Extractor
		// fields can be used in Falco rule conditions.
		// Required: yes
		// Return value: a string with the list of fields encoded as a json
		//   array.
		//   Each field entry is a json object with the following properties:
		//     "name": a string with a name for the field
		//     "type": one of "string", "uint64", "bool", "reltime", "abstime",
		//             "ipaddr", "ipnet"
		//     "isList: (optional) If present and set to true, notes
		//              that the field extracts a list of values.
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
		//    {"type": "uint64", "name": "field1", "desc": "Describing field 1"},
		//    {"type": "string", "name": "field2", "arg": {"isRequired": true, "isIndex": true}, "desc": "Describing field 2"},
		// ]
		const char* (*get_fields)();

		//
		// Extract one or more a filter field values from an event.
		// Required: yes
		// Arguments:
		// - evt: an event input provided by the framework.
		//   This is allocated by the framework, and it is not guaranteed
		//   that the event struct pointer is the same returned by the last
		//   next_batch() call.
		// - in: An input struct representing the extraction request.
		//   The input includes vtables containing callbacks that can be used by
		//   the plugin for performing read/write operations on a state table
		//   not owned by itelf, for which it obtained accessors at init time.
		//   The plugin does not need to go through this vtable in order
		//   to read and write from a table it owns.
		//
		// Return value: A ss_plugin_rc with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// The value of the ss_plugin_extract_field* output parameter must be
		// uniquely attached to the ss_plugin_t* parameter value. The pointer
		// must not be shared across multiple distinct ss_plugin_t* values.
		ss_plugin_rc (*extract_fields)(ss_plugin_t *s, const ss_plugin_event_input *evt, const ss_plugin_field_extract_input* in);
	};

	// Event parsing capability API
	struct
	{
		//
		// Return the list of event types that this plugin will receive
		// for event parsing. The event types follow the libscap specific.
		// This will be invoked only once by the framework after the plugin's
		// initialization. Events that are not included in the returned list
		// will not be received by the plugin.
		// 
		// This is a non-functional filter that should not influence the plugin's
		// functional behavior. Instead, this is a performance optimization
		// with the goal of avoiding unnecessary communication between the
		// framework and the plugin for events that are known to be not used for
		// event parsing. 
		//
		// Required: no
		//
		// This function is optional--if NULL or an empty array, then:
		// - the plugin will receive every event type if the result of
		//   get_parse_event_sources (either default or custom) is compatible
		//   with the "syscall" event source, otherwise
		// - the plugin will only receive events of plugin type (code 322).
		// todo(jasondellaluce): when/if major changes to v4, reorder the arguments
		// and put ss_plugin_t* as first
		uint16_t* (*get_parse_event_types)(uint32_t* numtypes, ss_plugin_t* s);
		//
		// Return a string describing the event sources that this plugin
		// is capable of parsing.
		//
		// Required: no
		//
		// Return value: a json array of strings containing event
		//   sources returned by a plugin with event sourcing capabilities get_event_source()
		//   function, or "syscall" for indicating support to non-plugin events.
		// This function is optional--if NULL or an empty array, then if plugin has sourcing capability,
		// and implements a specific event source, it will only receive events matching its event source,
		// otherwise it will receive events from all event sources.
		//
		const char* (*get_parse_event_sources)();
		//
		// Receives an event from the current capture and parses its content.
		// The plugin is guaranteed to receive an event at most once, after any
		// operation related the event sourcing capability, and before
		// any operation related to the field extraction capability.
		//
		// Required: yes
		//
		// Arguments:
		// - evt: an event input provided by the framework.
		//   This is allocated by the framework, and it is not guaranteed
		//   that the event struct pointer is the same returned by the last
		//   next_batch() call.
		// - in: A vtable containing callbacks that can be used by
		//   the plugin for performing read/write operations on a state table
		//   not owned by itelf, for which it obtained accessors at init time.
		//   The plugin does not need to go through this vtable in order
		//   to read and write from a table it owns.
		//
		// Return value: A ss_plugin_rc with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// The value of the ss_plugin_event_parse_input* output parameter must be
		// uniquely attached to the ss_plugin_t* parameter value. The pointer
		// must not be shared across multiple distinct ss_plugin_t* values.
		ss_plugin_rc (*parse_event)(ss_plugin_t *s, const ss_plugin_event_input *evt, const ss_plugin_event_parse_input* in);
	};

	// Async events capability API
	struct
	{
		//
		// Return a string describing the event sources for which this plugin
		// is capable of injecting async events in the event stream of a capture.
		// 
		// Required: no
		//
		// Return value: a json array of strings containing event
		//   sources returned by a plugin with event sourcing capabilities
		//   get_event_source() function, or "syscall" for indicating
		//   support to non-plugin events.
		// This function is optional--if NULL or an empty array, then async
		// events produced by this plugin will be injected in the event stream
		// of any data source.
		//
		const char* (*get_async_event_sources)();
		//
		// Return a string describing the name list of all asynchronous events
		// that this plugin is capable of pushing into a live event stream.
		// The framework rejects async events produced by a plugin if their
		// name is not on the name list returned by this function.
		//
		// Required: yes
		//
		// Return value: a non-empty json array of strings containing the
		//   names of the async events returned by a plugin.
		const char* (*get_async_events)();
		//
		// Sets a function handler that allows the plugin to send asynchronous
		// events to its owner during a live event capture. The handler is
		// a thread-safe function that can be invoked concurrently by
		// multiple threads. The asynchronous events must be encoded as
		// an async event type (code 402) as for the libscap specific.
		//
		// The plugin can start sending async events through the passed-in
		// handler right after returning from this function.
		// set_async_event_handler() can be invoked multiple times during the
		// lifetime of a plugin. In that case, the registered function handler
		// remains valid up until the next invocation of set_async_event_handler()
		// on the same plugin, after which the new handler set will replace any
		// already-set one. If the handler is set to a NULL function pointer,
		// the plugin is instructed about disabling or stopping the
		// production of async events. If a NULL handler is set, and an
		// asynchronous job has been started by the plugin before, the plugin
		// should stop the job and wait for it to be finished before returning
		// from this function. Although the event handler is thread-safe and
		// can be invoked concurrently, this function is still invoked
		// by the framework sequentially from the same thread.
		//
		// Async events encode a plugin ID that defines its event source.
		// However, this value is set by the framework when the async event
		// is received, and is set to the ID associated to the plugin-defined
		// event source currently open during a live capture, or zero in case
		// of the "syscall" event source. The event source assigned by the
		// framework to the async event can only be among the ones compatible
		// with the list returned by get_async_event_sources().
		//
		// Async events encode a string representing their event name, which is
		// used for runtime matching and define the encoded data payload.
		// Plugins are allowed to only send async events with one of the names
		// expressed in the list returned by get_async_events(). The name
		// of an async event acts as a contract on the encoding of the data
		// payload of all async events with the same name.
		// 
		// Required: yes
		// 
		// Arguments:
		// - owner: Opaque pointer to the plugin's owner. Must be passed
		//   as an argument to the async event function handler.
		// - handler: Function handler to be used for sending asynchronous
		//   events to the plugin's owner. The handler must be invoked with
		//   the same owner opaque pointer passed to this function, and with
		//   an event pointer owned and controlled by the plugin. The event
		//   pointer is not retained by the handler after it returns.
		//
		// Return value: A ss_plugin_rc with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
		//
		ss_plugin_rc (*set_async_event_handler)(ss_plugin_t* s, ss_plugin_owner_t* owner, const ss_plugin_async_event_handler_t handler);
	};
} plugin_api;

#ifdef __cplusplus
}
#endif
