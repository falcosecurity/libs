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

//
// Why isn't this parser written using antlr or some other parser generator?
// Essentially, after dealing with that stuff multiple times in the past, and fighting for a day
// to configure everything with crappy documentation and code that doesn't compile,
// I decided that I agree with this http://mortoray.com/2012/07/20/why-i-dont-use-a-parser-generator/
// and that I'm going with a manually written parser. The grammar is simple enough that it's not
// going to take more time. On the other hand I will avoid a crappy dependency that breaks my
// code at every new release, and I will have a cleaner and easier to understand code base.
//

#include <algorithm>
#include <iomanip>

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/utils.h>
#include <libsinsp/filter.h>
#include <libsinsp/filter/parser.h>
#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/plugin_filtercheck.h>
#include <libsinsp/filter_compare.h>

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_expression implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_filter_expression::add_check(std::unique_ptr<sinsp_filter_check> chk)
{
	m_checks.push_back(std::move(chk));
}

bool sinsp_filter_expression::compare(sinsp_evt *evt)
{
	bool res = true;

	sinsp_filter_check* chk = nullptr;

	auto size = m_checks.size();
	for(size_t j = 0; j < size; j++)
	{
		chk = m_checks[j].get();
		ASSERT(chk != NULL);

		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res = chk->compare(evt);
				break;
			case BO_NOT:
				res = !chk->compare(evt);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				if(res)
				{
					goto done;
				}
				res = chk->compare(evt);
				break;
			case BO_AND:
				if(!res)
				{
					goto done;
				}
				res = chk->compare(evt);
				break;
			case BO_ORNOT:
				if(res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				break;
			case BO_ANDNOT:
				if(!res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}
 done:
	return res;
}

bool sinsp_filter_expression::extract(sinsp_evt *evt, std::vector<extract_value_t>& values, bool sanitize_strings)
{
	return false;
}

int32_t sinsp_filter_expression::get_expr_boolop() const
{
	if(m_checks.size() <= 1)
	{
		return m_boolop;
	}

	// Reset bit 0 to remove irrelevant not
	boolop b0 = (boolop)((uint32_t)(m_checks.at(1)->m_boolop) & (uint32_t)~1);

	if(m_checks.size() <= 2)
	{
		return b0;
	}

	for(uint32_t l = 2; l < m_checks.size(); l++)
	{
		if((boolop)((uint32_t)(m_checks.at(l)->m_boolop) & (uint32_t)~1) != b0)
		{
			return -1;
		}
	}

	return b0;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter::sinsp_filter(sinsp *inspector)
{
	m_inspector = inspector;
	m_filter = std::make_unique<sinsp_filter_expression>();
	m_curexpr = m_filter.get();
}

void sinsp_filter::push_expression(boolop op)
{
	sinsp_filter_expression* newexpr = new sinsp_filter_expression();
	newexpr->m_boolop = op;
	newexpr->m_parent = m_curexpr;

	add_check(std::unique_ptr<sinsp_filter_check>(newexpr));
	m_curexpr = newexpr;
}

void sinsp_filter::pop_expression()
{
	ASSERT(m_curexpr->m_parent != NULL);

	if(m_curexpr->get_expr_boolop() == -1)
	{
		throw sinsp_exception("expression mixes 'and' and 'or' in an ambiguous way. Please use brackets.");
	}

	m_curexpr = m_curexpr->m_parent;
}

bool sinsp_filter::run(sinsp_evt *evt)
{
	return m_filter->compare(evt);
}

void sinsp_filter::add_check(std::unique_ptr<sinsp_filter_check> chk)
{
	m_curexpr->add_check(std::move(chk));
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_compiler implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_compiler::sinsp_filter_compiler(
		sinsp* inspector,
		const std::string& fltstr)
	: m_flt_str(fltstr),
	  m_factory(std::make_shared<sinsp_filter_factory>(inspector, m_default_filterlist))
{
}

sinsp_filter_compiler::sinsp_filter_compiler(
		std::shared_ptr<sinsp_filter_factory> factory,
		const std::string& fltstr)
	: m_flt_str(fltstr),
	  m_factory(factory)
{
}

sinsp_filter_compiler::sinsp_filter_compiler(
		std::shared_ptr<sinsp_filter_factory> factory,
		const libsinsp::filter::ast::expr* fltast)
	: m_flt_ast(fltast),
	  m_factory(factory)
{
}

std::unique_ptr<sinsp_filter> sinsp_filter_compiler::compile()
{
	m_warnings.clear();

	// parse filter string on-the-fly if not pre-parsed AST is provided
	if (m_flt_ast == NULL)
	{
		libsinsp::filter::parser parser(m_flt_str);
		try
		{
			m_internal_flt_ast = parser.parse();
			m_flt_ast = m_internal_flt_ast.get();
		}
		catch (const sinsp_exception& e)
		{
			throw sinsp_exception("filter error at "
				+ parser.get_pos().as_string() + ": " + e.what());
		}
	}

	// create new filter using factory,
	// setup compiler state and start compilation
	m_filter = m_factory->new_filter();
	m_last_boolop = BO_NONE;
	m_last_node_field = nullptr;
	m_last_node_field_is_plugin = false;
	try
	{
		m_flt_ast->accept(this);
	}
	catch (const sinsp_exception& e)
	{
		m_filter = nullptr;
		throw e;
	}

	// return compiled filter
	return std::move(m_filter);
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::and_expr* e)
{
	m_pos = e->get_pos();
	bool nested = m_last_boolop != BO_AND;
	if (nested)
	{
		m_filter->push_expression(m_last_boolop);
		m_last_boolop = BO_NONE;
	}
	for (auto &c : e->children)
	{
		c->accept(this);
		m_last_boolop = BO_AND;
	}
	if (nested)
	{
		m_filter->pop_expression();
	}
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::or_expr* e)
{
	m_pos = e->get_pos();
	bool nested = m_last_boolop != BO_OR;
	if (nested)
	{
		m_filter->push_expression(m_last_boolop);
		m_last_boolop = BO_NONE;
	}
	for (auto &c : e->children)
	{
		c->accept(this);
		m_last_boolop = BO_OR;
	}
	if (nested)
	{
		m_filter->pop_expression();
	}
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::not_expr* e)
{
	m_pos = e->get_pos();
	m_last_boolop = (boolop)((uint32_t)m_last_boolop | BO_NOT);
	m_filter->push_expression(m_last_boolop);
	m_last_boolop = BO_NONE;
	e->child->accept(this);
	m_filter->pop_expression();
}

static inline void check_op_type_compatibility(sinsp_filter_check& c)
{
	std::string err;
	auto fi = c.get_transformed_field_info();
	if (fi && !flt_is_comparable(c.m_cmpop, fi->m_type, fi->is_list(), err))
	{
		throw sinsp_exception("filter error: " + err);
	}
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::unary_check_expr* e)
{
	m_pos = e->get_pos();
	m_last_node_field = nullptr;
	m_last_node_field_is_plugin = false;
	e->left->accept(this);
	if (!m_last_node_field)
	{
		throw sinsp_exception("filter error: missing field in left-hand of unary check");
	}
	auto check = std::move(m_last_node_field);
	check->m_cmpop = str_to_cmpop(e->op);
	check->m_boolop = m_last_boolop;
	check_op_type_compatibility(*check);
	m_filter->add_check(std::move(check));
}

static void add_filtercheck_value(sinsp_filter_check* chk, size_t idx, std::string_view value)
{
	std::vector<char> hex_bytes;
	switch(chk->m_cmpop)
	{
		case CO_BCONTAINS:
		case CO_BSTARTSWITH:
			if(!sinsp_utils::unhex(value, hex_bytes))
			{
				throw sinsp_exception("filter error: bcontains and bstartswith operator support hex strings only");
			}
			chk->add_filter_value(&hex_bytes[0], hex_bytes.size(), idx);
			break;
		default:
			chk->add_filter_value(value.data(), value.size(), idx);
			break;
	}
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::binary_check_expr* e)
{
	m_pos = e->get_pos();
	m_last_node_field = nullptr;
	m_last_node_field_is_plugin = false;
	e->left->accept(this);
	if (!m_last_node_field)
	{
		throw sinsp_exception("filter error: missing field in left-hand of binary check");
	}
	
	auto left_from_plugin = m_last_node_field_is_plugin;
	auto check = std::move(m_last_node_field);
	check->m_cmpop = str_to_cmpop(e->op);
	check->m_boolop = m_last_boolop;
	check_op_type_compatibility(*check);

	// Read the right-hand values of the filtercheck.
	m_last_node_field_is_plugin = false;
	m_field_values.clear();
	e->right->accept(this);

	if (m_last_node_field)
	{
		// When the lhs is a plugin filter check and the rhs side is again a plugin filter check
		// we have an issue. Even if the 2 filter checks are different the memory for extracted values is provided by the plugin.
		// So when we call the second extraction on the rhs filter check the previously extracted value 
		// for the lhs filter check will be overridden.
		//
		// As a workaround we add a custom internal transformer `FTR_STORAGE` to the lhs filter check.
		// The only goal of this transformer is to copy the memory storage of the extracted values from the plugin to the transformer.
		// In this way when we have 2 extractions on a plugin filter check, the plugin will hold only the memory of the rhs filter check,
		// while the storage of the lhs will be kept by the `FTR_STORAGE` transformer.
		//
		// The steps are the following:
		// * check if both the filter checks (lhs and rhs) are plugin filter checks.
		// * if yes, check if they are associated with the same plugin instance, otherwise, this is not an issue. We use the plugin name
		//   to understand if the plugin is the same.
		// * if yes, add the `FTR_STORAGE` transformer to the lhs filter check.
		auto right_from_plugin = m_last_node_field_is_plugin;
		if (left_from_plugin && right_from_plugin)
		{
			check->add_transformer(filter_transformer_type::FTR_STORAGE);
		}

		// We found another field as right-hand side of the comparison
		check->add_filter_value(std::move(m_last_node_field));
	}
	else
	{
		// We found no field as right-hand side of the comparison, so we
		// assume to find some constant values.
		// For list-related operators ('in', 'intersects', 'pmatch'), the vector
		// can be filled with more than 1 value, whereas in all other cases we
		// expect the vector to only have 1 value. We don't check this here, as
		// the parser is trusted to apply proper grammar checks on this constraint.
		for (size_t i = 0; i < m_field_values.size(); i++)
		{
			check_value_and_add_warnings(e->right->get_pos(), m_field_values[i]);
			add_filtercheck_value(check.get(), i, m_field_values[i]);
		}
	}
	m_filter->add_check(std::move(check));
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::identifier_expr* e)
{
	m_pos = e->get_pos();
	throw sinsp_exception("filter error: unexpected identifier '" + e->identifier + "'");
}

void sinsp_filter_compiler::check_value_and_add_warnings(
		const libsinsp::filter::ast::pos_info& pos, const std::string& v)
{
	try
	{
		// remove all spaces to catch most common errors
		auto s = v;
		s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());

		// check if the string is a valid field
		if (m_factory->new_filtercheck(s.c_str()) != nullptr)
		{
			auto msg = "string '" + v
				+ "' may be a valid field wrongly interpreted as a string value";
			m_warnings.push_back({msg, pos});
		}

		// check if the string may be a valid transformer
		auto transformers = libsinsp::filter::parser::supported_field_transformers(true);
		for (const auto& t : transformers)
		{
			if (s.size() >= t.size() + 2
					&& s.compare(0, t.size(), t) == 0
					&& s[t.size()] == '('
					&& s.back() == ')')
			{
				auto msg = "string '" + v
					+ "' may be a valid field transformer wrongly interpreted as a string value";
				m_warnings.push_back({msg, pos});
			}
		}
	}
	catch (...)
	{
		// parsing invalid strings as fields may cause unexpected errors.
		// we're not interested in any of those, we just want to catch
		// success cases in order to emit a warning
	}
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::value_expr* e)
{
	m_pos = e->get_pos();
	m_field_values.clear();
	m_field_values.push_back(e->value);
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::list_expr* e)
{
	m_pos = e->get_pos();
	m_field_values = e->values;
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::field_expr* e)
{
	m_pos = e->get_pos();
	auto field_name = create_filtercheck_name(e->field, e->arg);
	m_last_node_field = create_filtercheck(field_name);
	m_last_node_field_is_plugin = dynamic_cast<sinsp_filter_check_plugin*>(m_last_node_field.get()) != nullptr;
	if (m_last_node_field->parse_field_name(field_name, true, true) == -1)
	{
		throw sinsp_exception("filter error: can't parse field expression '" + field_name + "'");
	}
}

void sinsp_filter_compiler::visit(const libsinsp::filter::ast::field_transformer_expr* e)
{
	m_pos = e->get_pos();
	m_last_node_field = nullptr;
	m_last_node_field_is_plugin = false;
	e->value->accept(this);
	if (!m_last_node_field)
	{
		throw sinsp_exception("filter error: found null child node on '" + e->transformer + "' transformer");
	}

	// apply transformer, ignoring the "identity one"
	if (e->transformer != "val")
	{
		m_last_node_field->add_transformer(filter_transformer_from_str(e->transformer));
	}
}

std::string sinsp_filter_compiler::create_filtercheck_name(const std::string& name, const std::string& arg)
{
	// The filtercheck factories parse the name + arg as a whole.
	// We keep this for now, but we may want to change this in the future.
	// todo(jasondellaluce): handle field arg parsing at compilation time
	std::string fld = name;
	if (arg.size() > 0)
	{
		fld += "[" + arg + "]";
	}
	return fld;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_compiler::create_filtercheck(std::string_view field)
{
	auto chk = m_factory->new_filtercheck(field);
	if(chk == NULL)
	{
		throw sinsp_exception("filter_check called with nonexistent field " + std::string(field));
	}
	return chk;
}

sinsp_filter_factory::sinsp_filter_factory(sinsp *inspector,
					   filter_check_list &available_checks)
	: m_inspector(inspector), m_available_checks(available_checks)
{
}

std::unique_ptr<sinsp_filter> sinsp_filter_factory::new_filter() const
{
	return std::make_unique<sinsp_filter>(m_inspector);
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_factory::new_filtercheck(std::string_view fldname) const
{
	return m_available_checks.new_filter_check_from_fldname(fldname,
								m_inspector,
								true);
}

std::list<sinsp_filter_factory::filter_fieldclass_info> sinsp_filter_factory::get_fields() const
{
	std::vector<const filter_check_info*> fc_plugins;
	m_available_checks.get_all_fields(fc_plugins);

	return check_infos_to_fieldclass_infos(fc_plugins);
}

std::list<sinsp_filter_factory::filter_fieldclass_info> sinsp_filter_factory::check_infos_to_fieldclass_infos(
	const std::vector<const filter_check_info*> &fc_plugins)
{
	std::list<sinsp_filter_factory::filter_fieldclass_info> ret;

	for(auto &fci : fc_plugins)
	{
		if(fci->m_flags & filter_check_info::FL_HIDDEN)
		{
			continue;
		}

		sinsp_filter_factory::filter_fieldclass_info cinfo;
		cinfo.name = fci->m_name;
		cinfo.desc = fci->m_desc;
		cinfo.shortdesc = fci->m_shortdesc;

		for(auto fld = fci->m_fields; fld != fci->m_fields + fci->m_nfields; ++fld)
		{
			// If a field is only used to organize events,
			// we don't want to print it and don't return it here.
			if(fld->m_flags & EPF_PRINT_ONLY)
			{
				continue;
			}

			sinsp_filter_factory::filter_field_info info;
			info.name = fld->m_name;
			info.desc = fld->m_description;
			info.data_type =  param_type_to_string(fld->m_type);

			if(fld->m_flags & EPF_FILTER_ONLY)
			{
				info.tags.insert("FILTER_ONLY");
			}

			if(fld->m_flags & EPF_TABLE_ONLY)
			{
				info.tags.insert("EPF_TABLE_ONLY");
			}

			if(fld->m_flags & EPF_DEPRECATED)
			{
				info.tags.insert("EPF_DEPRECATED");
			}

			if(fld->m_flags & EPF_NO_RHS)
			{
				info.tags.insert("EPF_NO_RHS");
			}

			if(fld->m_flags & EPF_NO_TRANSFORMER)
			{
				info.tags.insert("EPF_NO_TRANSFORMER");
			}

			if(fld->m_flags & EPF_ARG_REQUIRED)
			{
				info.tags.insert("ARG_REQUIRED");
			}
			else if(fld->m_flags & EPF_ARG_ALLOWED)
			{
				info.tags.insert("ARG_ALLOWED");
			}

			cinfo.fields.emplace_back(std::move(info));
		}

		ret.emplace_back(std::move(cinfo));
	}

	return ret;
}

bool sinsp_filter_factory::filter_field_info::is_skippable() const
{
	// Skip fields with the EPF_TABLE_ONLY flag.
	return (tags.find("EPF_TABLE_ONLY") != tags.end());
}

bool sinsp_filter_factory::filter_field_info::is_deprecated() const
{
	// Skip fields with the EPF_DEPRECATED flag.
	return (tags.find("EPF_DEPRECATED") != tags.end());
}

uint32_t sinsp_filter_factory::filter_fieldclass_info::s_rightblock_start = 30;
uint32_t sinsp_filter_factory::filter_fieldclass_info::s_width = 120;

void sinsp_filter_factory::filter_fieldclass_info::wrapstring(const std::string &in, std::ostringstream &os)
{
	std::istringstream is(in);
	std::string word;
	uint32_t len = 0;

	while (is >> word)
	{
		// + 1 is trailing space.
		uint32_t wordlen = word.length() + 1;

		if((len + wordlen) <= (s_width-s_rightblock_start))
		{
			len += wordlen;
		}
		else
		{
			os << std::endl;
			os << std::left << std::setw(s_rightblock_start) << " ";
			len = wordlen;
		}

		os << word << " ";
	}
}

std::string sinsp_filter_factory::filter_fieldclass_info::as_markdown(const std::set<std::string>& event_sources, bool include_deprecated)
{
	std::ostringstream os;
	uint32_t deprecated_count = 0;

	os << "## Field Class: " << name << std::endl << std::endl;

	if(desc != "")
	{
		os << desc << std::endl << std::endl;
	}

	if(!event_sources.empty())
	{
		os << "Event Sources: ";

		for(const auto &src : event_sources)
		{
			os << src << " ";
		}

		os << std::endl << std::endl;
	}

	os << "Name | Type | Description" << std::endl;
	os << ":----|:-----|:-----------" << std::endl;

	for(auto &fld_info : fields)
	{
		// Skip fields that should not be included
		// (e.g. hidden fields)
		if(fld_info.is_skippable())
		{
			continue;
		}
		if(!include_deprecated && fld_info.is_deprecated())
		{
			deprecated_count++;
			continue;
		}

		os << "`" << fld_info.name << "` | " << fld_info.data_type << " | " << fld_info.desc << std::endl;
	}

	if(deprecated_count == fields.size())
	{
		return "";
	}

	return os.str();
}

std::string sinsp_filter_factory::filter_fieldclass_info::as_string(bool verbose, const std::set<std::string>& event_sources, bool include_deprecated)
{
	std::ostringstream os;
	uint32_t deprecated_count = 0;

	os << "-------------------------------" << std::endl;

	os << std::left << std::setw(s_rightblock_start) << "Field Class:" << name;
	if(shortdesc != "")
	{
		os << " (" << shortdesc << ")";
	}
	os << std::endl;

	if(desc != "")
	{
		os << std::left << std::setw(s_rightblock_start) << "Description:";

		wrapstring(desc, os);
		os << std::endl;
	}

	if(!event_sources.empty())
	{
		os << std::left << std::setw(s_rightblock_start) << "Event Sources:";

		for(const auto &src : event_sources)
		{
			os << src << " ";
		}

		os << std::endl;
	}

	os << std::endl;

	for(auto &fld_info : fields)
	{
		// Skip fields that should not be included
		// (e.g. hidden fields)
		if(fld_info.is_skippable())
		{
			continue;
		}
		if(!include_deprecated && fld_info.is_deprecated())
		{
			deprecated_count++;
			continue;
		}

		if(fld_info.name.length() > s_rightblock_start)
		{
			os << fld_info.name << std::endl;
			os << std::left << std::setw(s_rightblock_start) << " ";
		}
		else
		{
			os << std::left << std::setw(s_rightblock_start) << fld_info.name;
		}

		// Append any tags, and if verbose, add the type, to the description.
		std::string desc = fld_info.desc;

		if(!fld_info.tags.empty())
		{
			std::string tagsstr = "(";
			for(const auto &tag : fld_info.tags)
			{
				if(tagsstr != "(")
				{
					tagsstr += ",";
				}

				tagsstr += tag;
			}

			tagsstr += ")";

			desc = tagsstr + " " + desc;
		}

		if(verbose)
		{
			desc = "(Type: " + fld_info.data_type + ") " + desc;
		}

		wrapstring(desc, os);
		os << std::endl;
	}

	if(deprecated_count == fields.size())
	{
		return "";
	}

	return os.str();
}
