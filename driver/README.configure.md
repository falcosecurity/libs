# Kernel module "configure" mechanism

## Rationale
The kernel module has several `#if` directives based on the linux kernel version,
to deal with breaking changes.
This unfortunately doesn't work when breaking changes are being backported by kernel providers.
Red Hat is known to do this, but they provide `RHEL_RELEASE_CODE` we can test against.

Eventually we hit some backported changes within the same RHEL release that gave us some headaches.
The last drop was EulerOS, which backports breaking changes without providing `RHEL_RELEASE_CODE` nor any other macro.

## Solution
We introduce a *configure-ish* mechanism mimicking autoconf `AC_TRY_COMPILE`.

The kernel module Makefile will include all the *sub-kmod* inside `configure` folder and compile them with the host kernel headers.
Based on the result of the compilation we'll define macros to be used in the `#if` directives.

### First use-case: `access_ok()`
Kernel change https://github.com/torvalds/linux/commit/96d4f267e introduced in 5.0 removed an argument from `access_ok()` function.
In the past we already covered RHEL backporting it with:
```c
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)) || (PPM_RHEL_RELEASE_CODE > 0 && PPM_RHEL_RELEASE_CODE >= PPM_RHEL_RELEASE_VERSION(8, 1))
#define ppm_access_ok(type, addr, size)	access_ok(addr, size)
#else
#define ppm_access_ok(type, addr, size)	access_ok(type, addr, size)
#endif
```
What about EulerOS and alike?

Now we have `ACCESS_OK_2` *sub-kmod* which is a basic kernel module calling:
```c
access_ok(0, 0);
```
If it builds, we'll add `-DHAS_ACCESS_OK_2` to `ccflags-y`.
The kernel module code of course has been changed to:
```c
#ifdef HAS_ACCESS_OK_2
#define ppm_access_ok(type, addr, size)	access_ok(addr, size)
#else
#define ppm_access_ok(type, addr, size)	access_ok(type, addr, size)
#endif
```

## How to add a new "configure" check
1. Create a new folder under `configure/` with a meaningful name. That has to be all UPPERCASE with underscores, because it will be used as a macro name, prefixed by HAS_ (e.g. `ACCESS_OK_2` generates `HAS_ACCESS_OK_2`).
2. Name the *sub-kmod* source `test.c`. CMake and the predefined Makefile relies on the name being `test.c`.
3. Update the kernel module code to use the new macro.
4. Bob's your uncle.
