#include "ppm_tp.h"

const char *tp_names[] = {
#define X(name, path) path,
	TP_FIELDS
#undef X
};

#ifndef __KERNEL__
#include <string.h>
tp_values tp_from_name(const char *tp_path)
{
	// Find last '/' occurrence to take only the basename
	const char *tp_name = strrchr(tp_path, '/');
	if (tp_name == NULL || strlen(tp_name) <= 1)
	{
		return -1;
	}

	tp_name++;
	for (int i = 0; i < TP_VAL_MAX; i++)
	{
		if (strcmp(tp_name, tp_names[i]) == 0)
		{
			return i;
		}
	}
	return -1;
}
#endif