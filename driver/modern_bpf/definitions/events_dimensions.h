#ifndef __EVENT_DIMENSIONS_H__
#define __EVENT_DIMENSIONS_H__

#include "vmlinux.h"

/* Here we have all the dimensions for fixed-size events.
 */

#define PARAM_LEN 2
#define HEADER_LEN sizeof(struct ppm_evt_hdr)

/// TODO: We have to move these in the event_table.c. Right now we don't
/// want to touch scap tables.
#define MKDIR_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN

#endif /* __EVENT_DIMENSIONS_H__ */