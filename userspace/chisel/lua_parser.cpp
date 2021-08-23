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
#include <iostream>
#include <fstream>
#include <memory>
#include "gen_filter.h"

#include "lua_parser.h"
#include "lua_parser_api.h"


extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

const static struct luaL_reg ll_filter [] =
{
	{"rel_expr", &lua_parser_cbacks::rel_expr},
	{"bool_op", &lua_parser_cbacks::bool_op},
	{"nest", &lua_parser_cbacks::nest},
	{"unnest", &lua_parser_cbacks::unnest},
	{NULL,NULL}
};

lua_parser::lua_parser(std::shared_ptr<gen_event_filter_factory> factory)
	: m_factory(factory), m_last_boolop(BO_NONE),
	  m_have_rel_expr(false), m_nest_level(0)
{
	m_filter.reset(m_factory->new_filter());
}

lua_parser::~lua_parser()
{
}

void lua_parser::register_callbacks(lua_State *ls, const char *lua_library_name)
{
	// Register our c++ defined functions
	luaL_openlib(ls, lua_library_name, ll_filter, 0);
}

std::shared_ptr<gen_event_filter> lua_parser::filter()
{
	return m_filter;
}

std::shared_ptr<gen_event_filter_factory> lua_parser::factory()
{
	return m_factory;
}
