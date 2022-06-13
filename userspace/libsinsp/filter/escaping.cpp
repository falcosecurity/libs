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

#include "escaping.h"
#include "sinsp_exception.h"

namespace libsinsp {
namespace filter {

std::string escape_str(const std::string& str)
{
	std::string res = "";
	size_t len = str.size();
	bool should_escape = false;
	for (size_t i = 0; i < len; i++)
	{
		switch(str[i])
		{
		case '\b':
			should_escape = true;
			res += "\\b";
			break;
		case '\f':
			should_escape = true;
			res += "\\f";
			break;
		case '\n':
			should_escape = true;
			res += "\\n";
			break;
		case '\r':
			should_escape = true;
			res += "\\r";
			break;
		case '\t':
			should_escape = true;
			res += "\\t";
			break;
		case ' ':
			should_escape = true;
			res += ' ';
			break;
		case '\\':
			should_escape = true;
			res += "\\\\";
			break;
		case '"':
			should_escape = true;
			res += "\\\"";
			break;
		case '\'':
			should_escape = true;
			res += "'";
			break;
		default:
			res += str[i];
		}
	}

	if(should_escape)
	{
		res = "\"" + res + "\"";
	}

	return res;
}

std::string unescape_str(const std::string& str)
{
	std::string res = "";
	size_t len = str.size() - 1;
	bool escaped = false;
	for (size_t i = 1; i < len; i++)
	{
		if (!escaped)
		{
			if (str[i] == '\\')
			{
				escaped = true;
			}
			else
			{
				res += str[i];
			}
		}
		else
		{
			switch(str[i])
			{
				case 'b':
					res += '\b';
					break;
				case 'f':
					res += '\f';
					break;
				case 'n':
					res += '\n';
					break;
				case 'r':
					res += '\r';
					break;
				case 't':
					res += '\t';
					break;
				case ' ':
					// NOTE: we may need to initially support this to not create breaking changes with
					// some existing wrongly-escaped rules. So far, I only found one, in Falco:
					// https://github.com/falcosecurity/falco/blob/204f9ff875be035e620ca1affdf374dd1c610a98/rules/falco_rules.yaml#L3046
					// todo(jasondellaluce): remove this once rules are rewritten with correct escaping
				case '\\':
					res += '\\';
					break;
				case '/':
					res += '/';
					break;
				case '"':
					if (str[0] != str[i])
					{
						throw sinsp_exception("invalid \\\" escape in '-quoted string");
					}
					res += '\"';
					break;
				case '\'':
					if (str[0] != str[i])
					{
						throw sinsp_exception("invalid \\' escape in \"-quoted string");
					}
					res += '\'';
					break;
				case 'x':
					// todo(jasondellaluce): support hex num escaping (not needed for now)
				default:
					throw sinsp_exception("unsupported string escape sequence: \\" + std::string(1, str[i]));
			}
			escaped = false;
		}
	}
	return res;
}

}
}
