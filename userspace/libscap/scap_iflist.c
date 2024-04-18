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

#include <stdio.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>

//
// Free a previously allocated list of interfaces
//
void scap_free_iflist(scap_addrlist* ifhandle)
{
	if(ifhandle)
	{
		if(ifhandle->v6list)
		{
			free(ifhandle->v6list);
		}

		if(ifhandle->v4list)
		{
			free(ifhandle->v4list);
		}

		free(ifhandle);
	}
}
