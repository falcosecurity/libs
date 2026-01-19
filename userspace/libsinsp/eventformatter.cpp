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

#include <libsinsp/sinsp.h>
#include <libsinsp/filterchecks.h>
#include <libsinsp/eventformatter.h>
#include <libsinsp/filter/parser.h>

static constexpr const char* s_not_available_str = "<NA>";

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector, filter_check_list& available_checks):
        m_inspector(inspector),
        m_available_checks(available_checks) {}

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector,
                                         const std::string& fmt,
                                         filter_check_list& available_checks):
        m_inspector(inspector),
        m_available_checks(available_checks) {
	output_format of = sinsp_evt_formatter::OF_NORMAL;

	if(m_inspector->get_buffer_format() == sinsp_evt::PF_JSON ||
	   m_inspector->get_buffer_format() == sinsp_evt::PF_JSONEOLS ||
	   m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEX ||
	   m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEXASCII ||
	   m_inspector->get_buffer_format() == sinsp_evt::PF_JSONBASE64) {
		of = sinsp_evt_formatter::OF_JSON;
	}

	set_format(of, fmt);
}

void sinsp_evt_formatter::set_format(output_format of, const std::string& fmt) {
	if(fmt.empty()) {
		throw sinsp_exception("empty formatting token");
	}

	m_output_tokens.clear();
	m_output_format = of;

	//
	// If the string starts with a *, it means that we are ok with printing
	// the string even when not all the values it specifies are set.
	//
	std::string lfmt(fmt);
	if(lfmt[0] == '*') {
		m_require_all_values = false;
		lfmt.erase(0, 1);
	} else {
		m_require_all_values = true;
	}

	//
	// Parse the string and extract the tokens
	//
	const char* cfmt = lfmt.c_str();
	std::shared_ptr<sinsp_filter_check> chk;
	uint32_t lfmtlen = (uint32_t)lfmt.length();
	uint32_t last_nontoken_str_start = 0;
	uint32_t j = 0;
	for(j = 0; j < lfmtlen; j++) {
		if(cfmt[j] == '%') {
			int toklen = 0;

			if(last_nontoken_str_start != j) {
				auto newtkn = std::make_shared<rawstring_check>(
				        lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
				m_output_tokens.emplace_back(newtkn);
				m_output_tokenlens.push_back(0);
			}

			if(j == lfmtlen - 1) {
				throw sinsp_exception("invalid formatting syntax: formatting cannot end with a %");
			}

			//
			// If the field specifier starts with a number, it means that we have a length
			// transformer
			//
			if(isdigit(cfmt[j + 1])) {
				//
				// Parse the token length
				//
				sscanf(cfmt + j + 1, "%d", &toklen);

				//
				// Advance until the beginning of the field name
				//
				while(true) {
					if(j == lfmtlen - 1) {
						throw sinsp_exception(
						        "invalid formatting syntax: formatting cannot end with a number");
					} else if(isdigit(cfmt[j + 1])) {
						j++;
						continue;
					} else {
						break;
					}
				}
			}

			// start parsing the token, which at this point must be a valid
			// field or a valid field transformer

			// first we find the atoms (aka a single field).

			bool found = false;
			uint32_t fsize = lfmt.substr(j + 1).size();
			std::unique_ptr<libsinsp::filter::ast::expr> ast;
			while(!found) {
				// TODO(therealbobo): possible optimization: split the formatter by '%'
				try {
					libsinsp::filter::parser parser(lfmt.substr(j + 1, fsize));
					ast = parser.parse_field_or_transformer();
					auto factory =
					        std::make_shared<sinsp_filter_factory>(m_inspector, m_available_checks);
					sinsp_extractor_compiler compiler(factory, ast.get());
					chk = compiler.compile();
					found = true;
					fsize = parser.get_pos().idx;
				} catch(sinsp_exception& e) {
					fsize--;
					if(fsize == 0) {
						throw sinsp_exception(std::string("unknown filter: ") + e.what());
					}
				}
			}

			auto factory = std::make_shared<sinsp_filter_factory>(m_inspector, m_available_checks);
			formatter_visitor(factory, m_resolution_tokens).fill(ast.get());

			j += fsize;
			ASSERT(j <= lfmtlen);

			m_output_tokens.emplace_back(chk);
			m_output_tokenlens.push_back(toklen);

			last_nontoken_str_start = j + 1;
		}
	}

	if(last_nontoken_str_start != j) {
		auto chk = std::make_shared<rawstring_check>(
		        lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
		m_output_tokens.emplace_back(chk);
		m_output_tokenlens.push_back(0);
	}
}

bool sinsp_evt_formatter::resolve_tokens(sinsp_evt* evt,
                                         std::map<std::string, std::string>& values) {
	for(const auto& t : m_resolution_tokens) {
		if(t.has_transformers && !m_resolve_transformed_fields) {
			continue;
		}

		const char* str = t.token->tostring(evt);
		if(str == NULL) {
			if(m_require_all_values) {
				return false;
			}

			str = s_not_available_str;
		}
		values[t.name] = str;
	}
	return true;
}

bool sinsp_evt_formatter::get_field_values(sinsp_evt* evt,
                                           std::map<std::string, std::string>& fields) {
	return resolve_tokens(evt, fields);
}

void sinsp_evt_formatter::get_field_names(std::vector<std::string>& fields) {
	for(const auto& t : m_resolution_tokens) {
		fields.emplace_back(t.name);
	}
}

sinsp_evt_formatter::output_format sinsp_evt_formatter::get_output_format() {
	return m_output_format;
}

bool sinsp_evt_formatter::tostring_withformat(sinsp_evt* evt,
                                              std::string& output,
                                              output_format of) {
	output.clear();

	if(of == OF_JSON) {
		bool retval = true;
		for(const auto& t : m_resolution_tokens) {
			if(t.has_transformers && !m_resolve_transformed_fields) {
				// always skip keys with transformers here
				// todo!: is this the desired behavior?
				continue;
			}
			Json::Value json_value = t.token->tojson(evt);
			if(json_value == Json::nullValue && m_require_all_values) {
				retval = false;
				break;
			}
			m_root[t.name] = t.token->tojson(evt);
		}
		output = m_writer.write(m_root);
		output = output.substr(0, output.size() - 1);
		return retval;
	}

	ASSERT(m_output_tokenlens.size() == m_output_tokens.size());
	for(size_t j = 0; j < m_output_tokens.size(); j++) {
		const char* str = m_output_tokens[j]->tostring(evt);
		if(str == NULL) {
			if(m_require_all_values) {
				return false;
			} else {
				str = s_not_available_str;
			}
		}

		uint32_t tks = m_output_tokenlens[j];
		if(tks != 0) {
			std::string sstr(str);
			sstr.resize(tks, ' ');
			output += sstr;
		} else {
			output += str;
		}
	}

	return true;
}

bool sinsp_evt_formatter::tostring(sinsp_evt* evt, std::string& res) {
	return tostring_withformat(evt, res, m_output_format);
}

sinsp_evt_formatter_factory::sinsp_evt_formatter_factory(sinsp* inspector,
                                                         filter_check_list& available_checks):
        m_inspector(inspector),
        m_available_checks(available_checks),
        m_output_format(sinsp_evt_formatter::OF_NORMAL) {}

void sinsp_evt_formatter_factory::set_output_format(sinsp_evt_formatter::output_format of) {
	m_formatters.clear();

	m_output_format = of;
}

std::shared_ptr<sinsp_evt_formatter> sinsp_evt_formatter_factory::create_formatter(
        const std::string& format) {
	auto it = m_formatters.find(format);

	if(it != m_formatters.end()) {
		return it->second;
	}

	auto ret = std::make_shared<sinsp_evt_formatter>(m_inspector, m_available_checks);

	ret->set_format(m_output_format, format);
	m_formatters[format] = ret;

	return ret;
}

formatter_visitor::formatter_visitor(const std::shared_ptr<sinsp_filter_factory>& factory,
                                     std::vector<resolution_token>& resolution_tokens):
        m_factory(factory),
        m_resolution_tokens(resolution_tokens) {}

void formatter_visitor::fill(const libsinsp::filter::ast::expr* ast) {
	ast->accept(this);
}

void formatter_visitor::visit(const libsinsp::filter::ast::and_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected 'and' expression in format string; "
	        "event formatting only supports field expressions, not boolean logic");
}

void formatter_visitor::visit(const libsinsp::filter::ast::or_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected 'or' expression in format string; "
	        "event formatting only supports field expressions, not boolean logic");
}

void formatter_visitor::visit(const libsinsp::filter::ast::not_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected 'not' expression in format string; "
	        "event formatting only supports field expressions, not boolean logic");
}

void formatter_visitor::visit(const libsinsp::filter::ast::identifier_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected identifier expression in format string; "
	        "event formatting only supports field expressions, not identifiers exprs");
}

void formatter_visitor::visit(const libsinsp::filter::ast::value_expr* e) {
	m_last_field_name = libsinsp::filter::ast::as_string(e);
}

void formatter_visitor::visit(const libsinsp::filter::ast::list_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected list expression in format string; "
	        "event formatting does not support list literals");
}

void formatter_visitor::visit(const libsinsp::filter::ast::transformer_list_expr* e) {
	// Visit children to register inner fields
	for(auto& c : e->children) {
		c->accept(this);
	}
	m_last_field_name = libsinsp::filter::ast::as_string(e);
}

void formatter_visitor::visit(const libsinsp::filter::ast::unary_check_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected unary check expression in format string; "
	        "event formatting only supports field expressions, not filter checks");
}

void formatter_visitor::visit(const libsinsp::filter::ast::binary_check_expr* e) {
	throw sinsp_exception(
	        "formatter_visitor: unexpected binary check expression in format string; "
	        "event formatting only supports field expressions, not filter checks");
}

void formatter_visitor::visit(const libsinsp::filter::ast::field_expr* e) {
	sinsp_extractor_compiler compiler(m_factory, e);
	m_last_field_name = libsinsp::filter::ast::as_string(e);
	m_resolution_tokens.emplace_back(m_last_field_name, compiler.compile(), false);
	m_is_last_transformer = false;
}

void formatter_visitor::visit(const libsinsp::filter::ast::field_transformer_expr* e) {
	sinsp_extractor_compiler compiler(m_factory, e);

	// Visit children to register inner fields/transformers
	for(auto& c : e->values) {
		c->accept(this);
	}

	// Use the existing as_string visitor instead of manually reconstructing
	std::string transformer_str = libsinsp::filter::ast::as_string(e);

	if(m_is_last_transformer) {
		m_resolution_tokens.pop_back();
	}
	m_resolution_tokens.emplace_back(transformer_str, compiler.compile(), true);
	m_last_field_name = transformer_str;
	m_is_last_transformer = true;
}
