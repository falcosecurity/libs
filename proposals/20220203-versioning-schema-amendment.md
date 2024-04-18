# Versioning schema

**Supersedes**: [20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme](20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme)

## Summary

This proposal extends and improves the two previous proposals regarding the versioning and the release process of the `falcosecurity/libs` repository (which includes libscap, libsinsp, and the two drivers).

In particular, the [20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme](20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme) proposal mandated to version all the artifacts as one single machinery with the spirit of simplicity. Although that was a good idea at the time of the first proposal, the new [20210818-driver-semver.md](20210818-driver-semver.md) proposal introduced an effective API versioning solution for the user/kernel boundary in order to make the drivers reusable across libscap consumers and their versions (when version compatibility allows).

This amendment introduces two different version numbers for releasing artifacts (instead of one single version number):

- The **libs version number** which represents the build version of the user-space libraries (i.e., libscap, libsinsp, and possibly any other further user-space library)
- The **driver version number** which represents the build version of kernel-space drivers (i.e., the kernel module, the eBPF probe, and possibly any other kernel-space driver)

This proposal does not aim to introduce changes other than using two different version numbers. Moreover, this proposal is only about the versions string used at build time, so no code changes are expected outside the build system context.

## Motivation

The [20210818-driver-semver.md](20210818-driver-semver.md#motivation) proposal is already fully implemented. The advantages introduced by that proposal would be lost if we used a single versioning number for all the artifacts as mandated by [20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme](20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme). Furthermore, that proposal is only about versioning the APIs that sits between the kernel and the user-space components. It does not mandate any specification regarding the versioning of artifacts.

This amendment is required to fill the gap between the two proposals and allow our users to reuse the same driver version across a range of compatible consumers.

## Goals

* Document the two versioning schemes (one for the libs and another for the drivers)
* Allow releasing libs and drivers separately (different timing and versioning)
* Make the drivers reusable across libscap consumers and their versions

## Non-goals

* Introduce code changes other than in the build system and in the documentation
* Indicate how the distribution of the artifacts must be implemented

## Proposed solution

### Userspace libs artifacts

Libscap and libsinsp are two distinct artifacts. They will be released with the same version number (a single [SemVer 2.0](https://semver.org/spec/v2.0.0.html) string). This proposal does not aim to change what already proposed by [20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme](20210524-versioning-and-release-of-the-libs-artifacts.md#versioning-scheme) with respect to the user-space components residing in `falcosecurity/libs`.


### Drivers artifacts

The kernel module and the eBPF probe are two components that can be built for any supported Kernel version. The source code of both drivers will be released with the same version number (a single [SemVer 2.0](https://semver.org/spec/v2.0.0.html) string).

However, a few considerations need to be taken into account. The public API is composed of two different characteristics in the driver context: the API functions (exposed to the consumer) and the data schema (delivered to the consumer). Our implementation versions those two characteristics directly in the source code (you can find the current versions respectively in [/driver/API_VERSION](/driver/API_VERSION) and [/driver/SCHEMA_VERSION](/driver/SCHEMA_VERSION)). Those versions use a SemVer compatible scheme.


For this reason, the **driver version number** must represent both characteristics, which form the public API for the drivers.

For that purpose, this document proposes to use `1.0.0` as the starting point for the driver version number, then to use the following rules to bump such version number: 
- *major* increases either when `API_VERSION`’s major or `SCHEMA_VERSION`’s major number has been increased
- *minor* increases either when `API_VERSION`’s minor or `SCHEMA_VERSION`’s minor number has been increased
- *patch* increases either when `API_VERSION`’s patch or `SCHEMA_VERSION`’s patch number has been increased or when any other code changes have been introduced (for example, the support for a new kernel)

Note that no backward-incompatible changes can be introduced without bumping the *major* number of `API_VERSION` or `SCHEMA_VERSION` first. Similar logic applies for the *minor* and *patch* numbers. Since both `API_VERSION` and `SCHEMA_VERSION` follow the SemVer scheme, with this method also, the resulting driver version is guaranteed to respect what the SemVer specification mandates.

### Other considerations

When releasing the artifacts, maintainers will use these versioning schemes (i.e., when git tagging libs or drivers).
However, consumers are free to use any versioning scheme they want by overriding those values at build time (e.g., via cmake options).

Steps described in the 
[20210524-versioning-and-release-of-the-libs-artifacts.md#steps](20210524-versioning-and-release-of-the-libs-artifacts.md#steps) section will need to be adapted to accommodate the two different release processes (one for the libs and another for the drivers).