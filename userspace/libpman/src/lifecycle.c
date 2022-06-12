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
	if(!g_state.cons_pos)
	{
		free(g_state.cons_pos);
	}

	if(!g_state.prod_pos)
	{
		free(g_state.prod_pos);
	}

	if(!g_state.skel)
	{
		bpf_probe__destroy(g_state.skel);
	}

	if(!g_state.rb_manager)
	{
		ring_buffer__free(g_state.rb_manager);
	}
}