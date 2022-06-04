#include "state.h"

static int setup_libbpf_print_verbose(enum libbpf_print_level level, const char* format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int setup_libbpf_print_no_verbose(enum libbpf_print_level level, const char* format, va_list args)
{
	if(level == LIBBPF_WARN)
	{
		return vfprintf(stderr, format, args);
	}
	return 0;
}

static void setup_libbpf_logging(bool verbosity)
{
	if(verbosity)
	{
		/* `libbpf_set_print` returns the old log function. */
		libbpf_set_print(setup_libbpf_print_verbose);
	}
	else
	{
		libbpf_set_print(setup_libbpf_print_no_verbose);
	}
}

int libpman__set_libbpf_configuration(bool verbosity)
{

	/* `LIBBPF_STRICT_ALL` turns on all supported strict features
	 * of libbpf to simulate libbpf v1.0 behavior.
	 * `libbpf_set_strict_mode` returns always 0.
	 */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set libbpf verbosity. */
	setup_libbpf_logging(verbosity);

	/* Set available number of CPUs inside the internal state. */
	g_state.n_cpus = libbpf_num_possible_cpus();
	if(g_state.n_cpus <= 0)
	{
		libpman__print_error("no available cpus");
		return -1;
	}
	return 0;
}

int libpman__get_cpus_number()
{
	return g_state.n_cpus;
}
