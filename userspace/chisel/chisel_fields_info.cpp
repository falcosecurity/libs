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
// Various helper functions to render stuff on the screen
//
#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <algorithm>

#include <libsinsp/sinsp.h>
#include <chisel/chisel.h>
#include <chisel/chisel_fields_info.h>

// Must match the value in the zsh tab completion
#define DESCRIPTION_TEXT_START 16

#define CONSOLE_LINE_LEN 79
#define PRINTF_WRAP_CPROC(x) #x
#define PRINTF_WRAP(x) PRINTF_WRAP_CPROC(x)

using namespace std;

struct summary_chisel_comparer
{
	bool operator()(const chisel_desc& first, const chisel_desc& second) const
	{
		return (first.m_category == second.m_category)
			       ? first.m_name < second.m_name
			       : first.m_category < second.m_category;
	}
};

void list_chisels(vector<chisel_desc>* chlist, bool verbose);

void print_chisel_info(chisel_desc* cd)
{
	// First we create a single list composed of
	// just this chisel and then run the short_description
	// over it in order to get those fields for free.
	std::vector<chisel_desc> chlist;
	chlist.push_back(cd[0]);

	list_chisels(&chlist, false);

	// Now we have to do the real work
	printf("\n");

	uint32_t l;
	string astr;

	string desc = cd->m_description;
	size_t desclen = desc.size();

	for(l = 0; l < desclen; l++)
	{
		if(l % CONSOLE_LINE_LEN == 0 && l != 0)
		{
			printf("\n");
		}

		printf("%c", desc[l]);
	}

	printf("\n");

	astr += "Args:\n";

	if(cd->m_args.size() != 0)
	{

		for(l = 0; l < cd->m_args.size(); l++)
		{
			astr += "[" + cd->m_args[l].m_type + "] " + cd->m_args[l].m_name + " - ";
			astr += cd->m_args[l].m_description + "\n";
		}
	}
	else
	{
		astr += "(None)";
	}

	size_t astrlen = astr.size();
	int linepos = 0;

	for(l = 0; l < astrlen; l++, linepos++)
	{
		if(astr[l] == '\n')
			linepos = -1;
		else if(linepos % (CONSOLE_LINE_LEN - DESCRIPTION_TEXT_START) == 0 && linepos != 0)
		{
			printf("\n%" PRINTF_WRAP(DESCRIPTION_TEXT_START) "s", "");
		}

		printf("%c", astr[l]);
	}

	// just for good measure
	printf("\n");
}

void list_chisels(vector<chisel_desc>* chlist, bool verbose)
{
	uint32_t j, l;

	//
	// Sort the list by name
	//
	sort(chlist->begin(), chlist->end(), summary_chisel_comparer());
	string last_category;

	//
	// Print the list to the screen
	//
	for(j = 0; j < chlist->size(); j++)
	{
		chisel_desc* cd = &(chlist->at(j));

		if(cd->m_viewinfo.m_valid)
		{
			continue;
		}

		string category = cd->m_category;

		if(category != last_category)
		{
			string fullcatstr = "Category: " + category;

			printf("\n%s\n", fullcatstr.c_str());
			for(l = 0; l < fullcatstr.size(); l++)
			{
				putchar('-');
			}

			printf("\n");
			last_category = category;
		}

		printf("%s", cd->m_name.c_str());
		uint32_t namelen = (uint32_t)cd->m_name.size();

		if(namelen >= DESCRIPTION_TEXT_START)
		{
			printf("\n");
			namelen = 0;
		}

		for(l = 0; l < (DESCRIPTION_TEXT_START - namelen); l++)
		{
			printf(" ");
		}

		string desc = cd->m_shortdesc;
		size_t desclen = desc.size();

		for(l = 0; l < desclen; l++)
		{
			if(l % (CONSOLE_LINE_LEN - DESCRIPTION_TEXT_START) == 0 && l != 0)
			{
				printf("\n%" PRINTF_WRAP(DESCRIPTION_TEXT_START) "s", "");
			}

			printf("%c", desc[l]);
		}

		printf("\n");
	}

	if(verbose)
	{
		printf("\nUse the -i flag to get detailed information about a specific chisel\n");
	}
}
