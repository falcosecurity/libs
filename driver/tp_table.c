#include "ppm_tp.h"

const char *tp_names[] = {
#define X(name, path) path,
	TP_FIELDS
#undef X
};