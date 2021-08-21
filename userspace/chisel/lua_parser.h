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

#include "lua_parser_api.h"
#include "gen_filter.h"

typedef struct lua_State lua_State;

class lua_parser
{
public:
	lua_parser(std::shared_ptr<gen_event_filter_factory> factory);
	virtual ~lua_parser();

	std::shared_ptr<gen_event_filter> filter();
	std::shared_ptr<gen_event_filter_factory> factory();

	static void register_callbacks(lua_State *ls, const char *lua_library_name);

 private:
	std::shared_ptr<gen_event_filter> m_filter;
	std::shared_ptr<gen_event_filter_factory> m_factory;

	boolop m_last_boolop;
	bool m_have_rel_expr;
	int32_t m_nest_level;

	friend class lua_parser_cbacks;
};

