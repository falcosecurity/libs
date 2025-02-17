#ifndef PLUGIN_ABI_VERSION
#define PLUGIN_ABI_VERSION 4
#if defined(__linux__) && defined(__x86_64__) && (defined(__GNUC__) || (__STDC_VERSION__ >= 201112L))
#include <assert.h>
#include <stddef.h>
static_assert(sizeof(((plugin_api*)0)->static_plugin_abi_version) == 8, "static_plugin_abi_version size mismatch");
static_assert(offsetof(plugin_api, static_plugin_abi_version) == 0, "static_plugin_abi_version offset mismatch");
static_assert(sizeof(((plugin_api*)0)->static_plugin_api_size) == 8, "static_plugin_api_size size mismatch");
static_assert(offsetof(plugin_api, static_plugin_api_size) == 8, "static_plugin_api_size offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_required_api_version) == 8, "get_required_api_version size mismatch");
static_assert(offsetof(plugin_api, get_required_api_version) == 16, "get_required_api_version offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_init_schema) == 8, "get_init_schema size mismatch");
static_assert(offsetof(plugin_api, get_init_schema) == 24, "get_init_schema offset mismatch");
static_assert(sizeof(((plugin_api*)0)->init) == 8, "init size mismatch");
static_assert(offsetof(plugin_api, init) == 32, "init offset mismatch");
static_assert(sizeof(((plugin_api*)0)->destroy) == 8, "destroy size mismatch");
static_assert(offsetof(plugin_api, destroy) == 40, "destroy offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_last_error) == 8, "get_last_error size mismatch");
static_assert(offsetof(plugin_api, get_last_error) == 48, "get_last_error offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_name) == 8, "get_name size mismatch");
static_assert(offsetof(plugin_api, get_name) == 56, "get_name offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_description) == 8, "get_description size mismatch");
static_assert(offsetof(plugin_api, get_description) == 64, "get_description offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_contact) == 8, "get_contact size mismatch");
static_assert(offsetof(plugin_api, get_contact) == 72, "get_contact offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_version) == 8, "get_version size mismatch");
static_assert(offsetof(plugin_api, get_version) == 80, "get_version offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_id) == 8, "get_id size mismatch");
static_assert(offsetof(plugin_api, get_id) == 88, "get_id offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_event_source) == 8, "get_event_source size mismatch");
static_assert(offsetof(plugin_api, get_event_source) == 96, "get_event_source offset mismatch");
static_assert(sizeof(((plugin_api*)0)->open) == 8, "open size mismatch");
static_assert(offsetof(plugin_api, open) == 104, "open offset mismatch");
static_assert(sizeof(((plugin_api*)0)->close) == 8, "close size mismatch");
static_assert(offsetof(plugin_api, close) == 112, "close offset mismatch");
static_assert(sizeof(((plugin_api*)0)->list_open_params) == 8, "list_open_params size mismatch");
static_assert(offsetof(plugin_api, list_open_params) == 120, "list_open_params offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_progress) == 8, "get_progress size mismatch");
static_assert(offsetof(plugin_api, get_progress) == 128, "get_progress offset mismatch");
static_assert(sizeof(((plugin_api*)0)->event_to_string) == 8, "event_to_string size mismatch");
static_assert(offsetof(plugin_api, event_to_string) == 136, "event_to_string offset mismatch");
static_assert(sizeof(((plugin_api*)0)->next_batch) == 8, "next_batch size mismatch");
static_assert(offsetof(plugin_api, next_batch) == 144, "next_batch offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_extract_event_types) == 8, "get_extract_event_types size mismatch");
static_assert(offsetof(plugin_api, get_extract_event_types) == 152, "get_extract_event_types offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_extract_event_sources) == 8, "get_extract_event_sources size mismatch");
static_assert(offsetof(plugin_api, get_extract_event_sources) == 160, "get_extract_event_sources offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_fields) == 8, "get_fields size mismatch");
static_assert(offsetof(plugin_api, get_fields) == 168, "get_fields offset mismatch");
static_assert(sizeof(((plugin_api*)0)->extract_fields) == 8, "extract_fields size mismatch");
static_assert(offsetof(plugin_api, extract_fields) == 176, "extract_fields offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_parse_event_types) == 8, "get_parse_event_types size mismatch");
static_assert(offsetof(plugin_api, get_parse_event_types) == 184, "get_parse_event_types offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_parse_event_sources) == 8, "get_parse_event_sources size mismatch");
static_assert(offsetof(plugin_api, get_parse_event_sources) == 192, "get_parse_event_sources offset mismatch");
static_assert(sizeof(((plugin_api*)0)->parse_event) == 8, "parse_event size mismatch");
static_assert(offsetof(plugin_api, parse_event) == 200, "parse_event offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_async_event_sources) == 8, "get_async_event_sources size mismatch");
static_assert(offsetof(plugin_api, get_async_event_sources) == 208, "get_async_event_sources offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_async_events) == 8, "get_async_events size mismatch");
static_assert(offsetof(plugin_api, get_async_events) == 216, "get_async_events offset mismatch");
static_assert(sizeof(((plugin_api*)0)->set_async_event_handler) == 8, "set_async_event_handler size mismatch");
static_assert(offsetof(plugin_api, set_async_event_handler) == 224, "set_async_event_handler offset mismatch");
static_assert(sizeof(((plugin_api*)0)->dump_state) == 8, "dump_state size mismatch");
static_assert(offsetof(plugin_api, dump_state) == 232, "dump_state offset mismatch");
static_assert(sizeof(((plugin_api*)0)->set_config) == 8, "set_config size mismatch");
static_assert(offsetof(plugin_api, set_config) == 240, "set_config offset mismatch");
static_assert(sizeof(((plugin_api*)0)->get_metrics) == 8, "get_metrics size mismatch");
static_assert(offsetof(plugin_api, get_metrics) == 248, "get_metrics offset mismatch");
static_assert(sizeof(((plugin_api*)0)->capture_open) == 8, "capture_open size mismatch");
static_assert(offsetof(plugin_api, capture_open) == 256, "capture_open offset mismatch");
static_assert(sizeof(((plugin_api*)0)->capture_close) == 8, "capture_close size mismatch");
static_assert(offsetof(plugin_api, capture_close) == 264, "capture_close offset mismatch");
#endif
#endif
