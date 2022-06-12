#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "state.h"

struct internal_state g_state;

void pman_print_error(const char* error_message)
{
	if(!error_message)
	{
		fprintf(stderr, "libpman: No specific message available (errno: %d | message: %s)\n", errno, strerror(errno));
	}
	else
	{
		fprintf(stderr, "libpman: %s (errno: %d | message: %s)\n", error_message, errno, strerror(errno));
	}
}