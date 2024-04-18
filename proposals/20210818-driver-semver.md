# API versioning for user/kernel boundary

## Summary

This proposal introduces [semver](https://semver.org/)-compatible version checks for the user/kernel boundary,
i.e. between the kernel driver/eBPF probe and the userspace components.

Currently, to ensure compatibility, the kernel module/eBPF probe must be built together
with libscap. Even though actual incompatibilities are few and far between, there's no
mechanism to tell whether a particular kernel module/eBPF probe is new enough to work
with a particular libscap build.

The version checks at present are:

1. For the eBPF probe, an exact match of the version of the probe/userspace components
is required.  The probe version is effectively the version number of the libscap *consumer*,
not directly related to libscap itself. E.g. two different consumer releases can use
the same libscap commit and still be unable to share the probes.

2. For the kernel module, there is no version check at all. The driver exposes an ioctl
to get the probe version (`PPM_IOCTL_GET_PROBE_VERSION`) but it is not used anywhere.
Again, what is versioned is the libscap consumer, not actual libscap.

## Motivation

Introducing a machine-usable API versioning scheme will let us:

1. Cut down the number of drivers needed to be built. Instead of a driver for each
(kernel version, consumer name, consumer version) tuple, we would only need one
for each (kernel version, driver API version). Given the relatively slow development
on the kernel side, a single driver API version might live for a long time

2. Make upgrades easier. Currently, the driver has to be unloaded and a new one loaded
in its place. With the API versioning scheme in place, usually there won't even
be a different driver. If there is one, it will usually be forwards-compatible,
even though it might miss some bug fixes. Only if the versions are truly incompatible,
an unload/reload will be required. Note that the API version can live in the module
*name* itself, which would let us have multiple versions loaded at the same time,
if we decide to go that way.

3. Ship the drivers in Linux distributions. With a single consumer-agnostic driver
per kernel, it becomes realistic for Linux distributions to ship a prebuilt driver
for their kernels. That would make all libscap consumers work out of the box,
without worrying about shipping the driver.

4. Support older consumer versions with new kernels. Whenever a new kernel comes out,
drivers need to be built to support it. These drivers currently cannot be used
for older consumer releases, even though there are no technical issues that would
prevent it.

## Goals

* Make the drivers reusable across libscap consumers and their versions

## Non-goals

* Make the drivers reusable across kernel versions (this is probably impossible
  in a general way for the kernel module, but BTF/CO-RE may help for the eBPF
  probe).

## The plan

1. Introduce an API version embedded in the userspace and kernel code
  * The version number will be a single 64-bit number that can be decomposed
    to the three semantic versioning components (major, minor, patch)
  * As long as the API version is kept separate from any preexisting
    consumer version numbers, the API version can start at 1.0.0.
    The easiest way to accomplish this would be to rename the driver
    (step 4).

2. Extend the review process to ensure the API version is incremented when needed.
  Note that e.g. adding support for a new kernel should not result in an API
  version increase (if the driver failed to build for that particular kernel
  before).

3. Verify the API version of the kernel module/eBPF probe when starting
  the libscap consumer:
  * different major versions cause a hard error
  * kernel minor < userspace minor causes a hard error
  * kernel minor == userspace minor and kernel patch < userspace patch causes
    a warning (the driver is compatible but has known bugs, fixed in later
    versions)

4. Deemphasize consumer name and version from the libscap build process
  * The driver should be named `scap` by default and use the API version to identify
    itself
  * An option may remain to override the driver name (and supply a version)
    but it should not be used without good reason

## The non-plan

This proposal does not address changes to the infrastructure that consumer
projects may have to build and distribute drivers. To fully realize the benefits
of this proposal, such infrastructure would have to be adapted to use e.g.
`scap_probe-<API_VERSION>-<KERNEL_VERSION>` as the identifier for a particular
probe, instead of `<CONSUMER>_probe-<CONSUMER_VERSION>-<KERNEL_VERSION>`.

Since the last point of the plan changes the module name, consumers having
said infrastructure will have to make these changes before upgrading
to a libscap version implementing that point. We might devise a plan to smooth
the transition (e.g. allow building the driver under both names for a while).
