#pragma once

#include <helpers/base/maps_getters.h>

static __always_inline bool attached_programs__capture_enabled()
{
	return maps__get_capture_flag();
}
