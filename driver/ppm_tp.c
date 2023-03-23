#include "ppm_tp.h"

const char *kmod_prog_names[] = {
#define X(name, path) path,
	KMOD_PROGS
#undef X
};
