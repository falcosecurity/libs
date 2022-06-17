# Release Processes

As per the [Versioning and release process of the libs artifacts](https://github.com/falcosecurity/libs/blob/master/proposals/20210524-versioning-and-release-of-the-libs-artifacts.md), this repository includes different groups of artifacts that needs to be versioned and released. Moreover, those artifacts follows different versioning schemas (see the [Driver SemVer](https://github.com/falcosecurity/libs/blob/master/proposals/20210818-driver-semver.md) and [Versioning schema](https://github.com/falcosecurity/libs/blob/master/proposals/20220203-versioning-schema-amendment.md)) proposals).

We have two separate release processes which occur **independently** of each other: 
- The **drivers release**
- The **libs release** (ie. _libsinp_ and _libscap_)

The drivers release process is mainly automated and happens outside this repository. The actual building and distribution system is implemented in our [test-infra](https://github.com/falcosecurity/test-infra) by the [Driverkit Build Grid](https://github.com/falcosecurity/test-infra/tree/master/driverkit), and drivers are published to https://download.falco.org/?prefix=driver/. The [drivers versioning](#Drivers-versioning) process happens in this repo. 

>_Note that not all versioned releases will be built and distributed. Drivers distribution is indeed implemented and maintained only to satisfy Falco's needs._

The libs release process is currently under development and limited to the versioning process only. The [libs versioning](#Libs-versioning) process happens in this repo.


## Release procedure

Regardless if it is a driver or a libs release when initiating a new release, we do the following process:

1. We decide together (usually in the #falco channel in [slack](https://kubernetes.slack.com/messages/falco)) if the source code is a good shape and if it's the case to be released
2. We double-check if the versioning rules have been respected (see sections below), then we pick the next version number to tag (i.e., a _git tag_)
3. A person with repository rights creates a [new release using the GitHub UI](https://github.com/falcosecurity/libs/releases/new) (a git tag will be automatically created)

> _At the time of writing, no other steps are needed since the whole release process is still in development. This document will be updated once the definitive process is fully implemented._


## Drivers versioning

The *driver version number* represents the build version of kernel-space drivers (i.e., the kernel module, the eBPF probe, and possibly any other kernel-space drivers).

**Requirements**

- The version MUST be a [SemVer 2.0](https://semver.org/spec/v2.0.0.html) string.

- Since our driver APIs are assumed to be stable, the major version number MUST be equal to or greater than `1`.

- To pick a new driver version number:

    1. The [API for user/kernel boundary](https://github.com/falcosecurity/libs/blob/master/proposals/20210818-driver-semver.md) is versioned in the source code. You MUST ensure the two files below have been updated by following the rules described in [driver/README.VERSION.md](https://github.com/falcosecurity/libs/blob/master/driver/README.VERSION.md):
        - [driver/API_VERSION](https://github.com/falcosecurity/libs/blob/master/driver/API_VERSION)
        - [driver/SCHEMA_VERSION](https://github.com/falcosecurity/libs/blob/master/driver/SCHEMA_VERSION)
    
        If not, open a PR to fix them.

    2. Compute the *driver version number* by strictly following the [Versioning Schema](https://github.com/falcosecurity/libs/blob/master/proposals/20220203-versioning-schema-amendment.md#drivers-artifacts) proposal's rules.

> _Note that `API_VERSION` and `SCHEMA_VERSION` are only used internally. On the other hand, only the **driver version number** will be used **to tag a new release**._



## Libs versioning

The *libs version number* represents a software version of the user-space libraries (i.e., libscap, libsinsp, and possibly any other further user-space library), and it is not tied to the drivers version numbering.

**Requirements**

- The version MUST be a [SemVer 2.0](https://semver.org/spec/v2.0.0.html) string.

- Since our userspace APIs are not yet stable, the major version number MUST be `0` (see the SemVer section about the [initial development phase](https://semver.org/spec/v2.0.0.html#how-should-i-deal-with-revisions-in-the-0yz-initial-development-phase)).

- The [Plugin API](./userspace/libscap/plugin_info.h) is versioned in the code and follow a semver-like numbering scheme. If any changes have been made to the Plugin API since the last release, you MUST ensure the Plugin API version is updated accordingly. If not, open a PR to fix it.