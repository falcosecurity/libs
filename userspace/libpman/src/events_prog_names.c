#include "state.h"

#include "events_prog_names.h"

#ifdef TEST_HELPERS
/// TODO: move in prog_names.c
const char* pman_get_event_prog_name(int event_type)
{
	return event_prog_names[event_type];
}

const char* pman_get_extra_event_prog_name(int event_type)
{
	return extra_event_prog_names[event_type];
}
#endif