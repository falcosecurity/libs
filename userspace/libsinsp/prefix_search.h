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

#include <string.h>

#include <string>
#include <sstream>
#include <list>
#include <unordered_map>

#include <libsinsp/filter_value.h>
#include <libsinsp/utils.h>

namespace path_prefix_map_ut
{
	typedef std::list<std::string> filter_components_t;

        // Split path /var/log/messages into a list of components (var, log, messages). Empty components are skipped.
	void split_path(const filter_value_t &path, filter_components_t &components);
};

//
// A data structure that allows testing a path P against a set of
// search paths S. The search succeeds if any of the search paths Si
// is a prefix of the path P.
//
// Here are some examples:
// - search(/var/run/docker, [/var/run, /etc, /lib, /usr/lib])
//         succeeds because /var/run is a prefix of /var/run/docker.
// - search(/boot, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /boot.
// - search(/var/lib/messages, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /var/lib/messages.
//         /var is a partial match but not /var/run.
// - search(/var, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /var
//         /var is a partial match but the search path is /var/run, not /var.

template<class Value>
class path_prefix_map
{
public:
	path_prefix_map();
	virtual ~path_prefix_map();

	void add_search_path(const char *path, Value &v);
	void add_search_path(const filter_value_t &path, Value &v);
	void add_search_path(const std::string &str, Value &v);

	// Similar to add_search_path, but takes a path already split
	// into a list of components. This allows for custom splitting
	// of paths other than on '/' boundaries.
	void add_search_path_components(const path_prefix_map_ut::filter_components_t &components, Value &v);

	// If non-NULL, Value is not allocated. It points to memory
	// held within this path_prefix_map() and is only valid as
	// long as the map exists.
	Value * match(const char *path);
	Value * match(const filter_value_t &path);

	Value *match_components(const path_prefix_map_ut::filter_components_t &components);

	std::string as_string(bool include_vals);

private:

	std::string as_string(const std::string &prefix, bool include_vals);
	std::string as_string(const std::string &prefix, bool include_vals,
			      const std::string& key,
			      std::pair<path_prefix_map *, Value *>& val);

	typedef std::unordered_map<std::string,
		std::pair<path_prefix_map *, Value *>> path_map_t;

	// Only used for as_string() and consistent outputs
	typedef std::map<std::string,
		std::pair<path_prefix_map *, Value *>> ordered_path_map_t;

	void add_search_path_components(const path_prefix_map_ut::filter_components_t &components,
					path_prefix_map_ut::filter_components_t::const_iterator comp,
					Value &v);

	void add_search_path_components(const path_prefix_map_ut::filter_components_t &components,
					path_prefix_map_ut::filter_components_t::const_iterator comp,
					Value &v,
					path_map_t& dirs);

	Value *match_components(const path_prefix_map_ut::filter_components_t &components,
				path_prefix_map_ut::filter_components_t::const_iterator comp);

	Value *match_components_direct(const path_prefix_map_ut::filter_components_t &components,
				       path_prefix_map_ut::filter_components_t::const_iterator comp);

	Value *match_components_glob(const path_prefix_map_ut::filter_components_t &components,
				     path_prefix_map_ut::filter_components_t::const_iterator comp);

	Value *check_match_value(std::pair<path_prefix_map *, Value*>& val,
				 const path_prefix_map_ut::filter_components_t &components,
				 path_prefix_map_ut::filter_components_t::const_iterator comp);

	// This is used *only* for components that do not contain glob
	// characters.
	// Maps from the path component at the current level to a
	// prefix search for the sub-path below the current level.
	// For example, if the set of search paths is (/var/run, /etc,
	// /lib, /usr, /usr/lib, /var/lib, /var/run), m_dirs contains:
	//   - (var, path_prefix_map(/run)
	//   - (etc, NULL)
	//   - (lib, NULL)
	//   - (usr, NULL)
	//   - (var, path_prefix_map(/lib, /run)
	// Note that because usr is a prefix of /usr/lib, the /usr/lib
	// path is dropped and only /usr is kept.  Also note that
	// terminator paths have a NULL path_prefix_map object.

	path_map_t m_dirs;

	// Maps from a wildcard pattern at the current level to a
	// prefix search for the sub-path below the current
	// level. This behaves identically to m_dirs, it's just that
	// the lookup is done by iterating over the keys and doing
	// sinsp_utils::glob_match for each.
	path_map_t m_glob_dirs;
};

template<class Value>
path_prefix_map<Value>::path_prefix_map()
{
}

template<class Value>
path_prefix_map<Value>::~path_prefix_map()
{
	for (auto &ent : m_dirs)
	{
		delete(ent.second.first);
		delete(ent.second.second);
	}

	for (auto &ent : m_glob_dirs)
	{
		delete(ent.second.first);
		delete(ent.second.second);
	}
}

template<class Value>
void path_prefix_map<Value>::add_search_path(const char *path, Value &v)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return add_search_path(mem, v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path(const std::string &str, Value &v)
{
	filter_value_t mem((uint8_t *) str.c_str(), (uint32_t) str.length());
	return add_search_path(mem, v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path(const filter_value_t &path, Value &v)
{
	path_prefix_map_ut::filter_components_t components;

	path_prefix_map_ut::split_path(path, components);

	// Add an initial "root" to the set of components. That
	// ensures that a top-level path of '/' still results in a
	// non-empty components list. For all other paths, there will
	// be a dummy 'root' prefix at the top of every path.
	components.emplace_front("root");

	return add_search_path_components(components, v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path_components(const path_prefix_map_ut::filter_components_t &components, Value &v)
{
	add_search_path_components(components, components.begin(), v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path_components(const path_prefix_map_ut::filter_components_t &components,
							path_prefix_map_ut::filter_components_t::const_iterator comp,
							Value &v)
{
	// If the component contains glob wildcard characters, add it
	// to m_glob_dirs
	if(comp->find_first_of("?*[") != std::string::npos)
	{
		add_search_path_components(components, comp, v, m_glob_dirs);
	}
	else
	{
		add_search_path_components(components, comp, v, m_dirs);
	}
}

template<class Value>
void path_prefix_map<Value>::add_search_path_components(const path_prefix_map_ut::filter_components_t &components,
							path_prefix_map_ut::filter_components_t::const_iterator comp,
							Value &v,
							path_prefix_map<Value>::path_map_t& dirs)
{
	path_prefix_map *subtree = NULL;

	// If the component contains glob wildcard characters, add it to m_glob_dirs

	auto it = dirs.find(*comp);
	auto cur = comp;
	comp++;

	if(it == dirs.end())
	{
		// This path component doesn't match any existing
		// dirent. We need to add one and its subtree.
		if(comp != components.end())
		{
			subtree = new path_prefix_map();
			subtree->add_search_path_components(components, comp, v);
		}

		// If the path doesn't have anything remaining, we
		// also add the value here.
		dirs[*cur] = std::pair<path_prefix_map*,Value *>(subtree, (comp == components.end() ? new Value(v) : NULL));
	}
	else
	{
		// An entry for this dirent already exists. We will
		// either add a new entry to the subtree, do nothing,
		// or get rid of the existing subtree.
		if(comp == components.end())
		{
			// This path is a prefix of the current path and we
			// can drop the existing subtree. For example, we can
			// drop /usr/lib when adding /usr.
			delete(it->second.first);
			delete(it->second.second);
			dirs.erase(*cur);
			dirs[*cur] = std::pair<path_prefix_map*,Value*>(NULL, new Value(v));
		}
		else if(it->second.first == NULL)
		{
			// The existing path is shorter than the
			// current path, in which case we don't have
			// to do anything. For example, no need to add
			// /usr/lib when /usr exists.
		}
		else
		{
			// We need to add the remainder to the
			// sub-tree's search path.
			it->second.first->add_search_path_components(components, comp, v);
		}
	}
}

template<class Value>
Value *path_prefix_map<Value>::match(const char *path)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return match(mem);
}

template<class Value>
Value *path_prefix_map<Value>::match(const filter_value_t &path)
{
	path_prefix_map_ut::filter_components_t components;

	path_prefix_map_ut::split_path(path, components);

	// Add an initial "root" to the set of components. That
	// ensures that a top-level path of '/' still results in a
	// non-empty components list. For all other paths, there will
	// be a dummy 'root' prefix at the top of every path.
	components.emplace_front("root");

	return match_components(components);
}

template<class Value>
Value *path_prefix_map<Value>::match_components(const path_prefix_map_ut::filter_components_t &components)
{
	return match_components(components, components.begin());
}

template<class Value>
Value *path_prefix_map<Value>::match_components(const path_prefix_map_ut::filter_components_t &components,
						path_prefix_map_ut::filter_components_t::const_iterator comp)
{

	Value *ret = match_components_direct(components, comp);

	if (ret != NULL)
	{
		return ret;
	}

	return match_components_glob(components, comp);
}

template<class Value>
Value *path_prefix_map<Value>::match_components_direct(const path_prefix_map_ut::filter_components_t &components,
						       path_prefix_map_ut::filter_components_t::const_iterator comp)
{
	auto it = m_dirs.find(*comp);

	if(it == m_dirs.end())
	{
		return NULL;
	}
	else
	{
		return check_match_value(it->second, components, ++comp);
	}
}

template<class Value>
Value *path_prefix_map<Value>::match_components_glob(const path_prefix_map_ut::filter_components_t &components,
						     path_prefix_map_ut::filter_components_t::const_iterator comp)
{
	for(auto& it : m_glob_dirs)
	{
		if(sinsp_utils::glob_match(it.first.c_str(), comp->c_str(), false))
		{
			Value *v = check_match_value(it.second, components, ++comp);
			if(v != NULL)
			{
				return v;
			}
		}
	}

	return NULL;
}

template<class Value>
Value *path_prefix_map<Value>::check_match_value(std::pair<path_prefix_map *, Value*>& val,
						 const path_prefix_map_ut::filter_components_t &components,
						 path_prefix_map_ut::filter_components_t::const_iterator comp)
{
	// If there is nothing left in the match path, the
	// subtree must be null. This ensures that /var
	// matches only /var and not /var/lib
	if(comp == components.end())
	{
		if(val.first == NULL)
		{
			return val.second;
		}
		else
		{
			return NULL;
		}
	}
	else if(val.first == NULL)
	{
		// /foo/bar matched a prefix /foo, so we're
		// done.
		return val.second;
	}
	else
	{
		return val.first->match_components(components, comp);
	}
}


template<class Value>
std::string path_prefix_map<Value>::as_string(bool include_vals)
{
	return as_string(std::string(""), include_vals);
}

template<class Value>
std::string path_prefix_map<Value>::as_string(const std::string& prefix,
					      bool include_vals,
					      const std::string& key,
					      std::pair<path_prefix_map *, Value *>& val)

{
	std::ostringstream os;

	os << prefix << key << " ->";
	if (include_vals && val.first == NULL)
	{
		os << " v=" << (*val.second);
	}

	os << std::endl;

	if(val.first)
	{
		std::string indent = prefix;
		indent += "    ";
		os << val.first->as_string(indent, include_vals);
	}

	return os.str();
};

template<class Value>
std::string path_prefix_map<Value>::as_string(const std::string &prefix, bool include_vals)
{
	std::ostringstream os;

	ordered_path_map_t ordered_dirs(m_dirs.begin(), m_dirs.end());
	for (auto &it : ordered_dirs)
	{
		os << as_string(prefix, include_vals, it.first, it.second);
	}

	ordered_path_map_t ordered_glob_dirs(m_glob_dirs.begin(), m_glob_dirs.end());
	for (auto &it : ordered_glob_dirs)
	{
		os << as_string(prefix, include_vals, it.first, it.second);
	}

	return os.str();
}

class path_prefix_search : public path_prefix_map<bool>
{
public:
	path_prefix_search() = default;
	virtual ~path_prefix_search() = default;

	void add_search_path(const char *path);
	void add_search_path(const filter_value_t &path);
	void add_search_path(const std::string &str);

	// If non-NULL, Value is not allocated. It points to memory
	// held within this path_prefix_map() and is only valid as
	// long as the map exists.
	bool match(const char *path);
	bool match(const filter_value_t &path);

	std::string as_string();
};
