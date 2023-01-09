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

#include "state.h"

int pman_open_probe()
{
	g_state.skel = bpf_probe__open();
	if(!g_state.skel)
	{
		pman_print_error("failed to open BPF skeleton");
		return errno;
	}
	return 0;
}

int pman_load_probe()
{
	if(bpf_probe__load(g_state.skel))
	{
		pman_print_error("failed to load BPF object");
		return errno;
	}
	return 0;
}

void pman_close_probe()
{
	if(g_state.cons_pos)
	{
		free(g_state.cons_pos);
	}

	if(g_state.prod_pos)
	{
		free(g_state.prod_pos);
	}

	if(g_state.skel)
	{
		bpf_probe__detach(g_state.skel);
		bpf_probe__destroy(g_state.skel);
	}

	if(g_state.rb_manager)
	{
		ring_buffer__free(g_state.rb_manager);
	}
}