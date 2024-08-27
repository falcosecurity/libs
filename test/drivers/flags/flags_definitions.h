#pragma once

#include <sys/syscall.h>

/* capabilities */
#if defined(__NR_capget) && defined(__NR_capset)

#include <sys/capability.h>
uint64_t capabilities_to_scap(unsigned long caps);

#endif /* __NR_capget */
