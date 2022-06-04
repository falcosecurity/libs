#include "state.h"

int libpman__open_probe()
{
	g_state.skel = bpf_probe__open();
	if(!g_state.skel)
	{
		libpman__print_error("failed to open BPF skeleton");
		return errno;
	}
	return 0;
}

int libpman__load_probe()
{
	if(bpf_probe__load(g_state.skel))
	{
		libpman__print_error("failed to load BPF object");
		return errno;
	}
	return 0;
}

void libpman__close_probe()
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