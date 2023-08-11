# Release Process

As per the [Versioning and release process of the libs artifacts](https://github.com/falcosecurity/libs/blob/master/proposals/20210524-versioning-and-release-of-the-libs-artifacts.md), this repository includes different components which are versioned (see the [Driver SemVer](https://github.com/falcosecurity/libs/blob/master/proposals/20210818-driver-semver.md) and [Versioning schema](https://github.com/falcosecurity/libs/blob/master/proposals/20220203-versioning-schema-amendment.md) proposals) and released individually.

The two releases, which may occur either concurrently or independently of each other, are: 

- The **drivers release**

    The [drivers versioning](#drivers-versioning) process happens in this repository, but their release process is mainly automated and managed in our [test-infra](https://github.com/falcosecurity/test-infra). Building is implemented there as per the [Driverkit Build Grid](https://github.com/falcosecurity/test-infra/tree/master/driverkit), and drivers are published to https://download.falco.org/?prefix=driver/. Drivers distribution is implemented and maintained only to satisfy Falco's needs.
        
- The **libs release** (ie. _libsinp_ and _libscap_)

    The [libs versioning](#libs-versioning) process happens in this repository. This release process is currently limited to the versioning only: and no artifacts are built nor distributed.

Commonly, we plan a release process when needed by [Falco](https://github.com/falcosecurity/falco). In such cases, we usually release both drivers and libs versions simultaneously. Other releases may occur for hotfixes or at the discretion of maintainers. Releases are mainly used to signal points in time where the source code is assumed to be consistent and stable.

Releases are planned using [GitHub milestones](https://github.com/falcosecurity/libs/milestones). The due date indicate when consumers should expected a tagged release.

Completed releases are denoted by a _git tag_ and a corresponding [GitHub release](https://github.com/falcosecurity/libs/releases).

## Release team

The release team consists of a *release manager* and other contributors from the community. Usually, we seek volunteers during our [community calls](https://github.com/falcosecurity/community#community-calls) or in the [#falco channel on Slack](https://kubernetes.slack.com/messages/falco), and then decide together the release planning.

The release manager's responsibility is to coordinate the release process. The release manager will create a GitHub issue to track the progress and announce the [release phases](#release-phases).

Note that the release manager does not need to be a maintainer. However, two [maintainers](https://github.com/falcosecurity/libs/blob/master/OWNERS) with repository rights must be part of the team to approve PRs, do the git tags, manage GitHub milestones, etc.

## Release Phases

Regardless if it is a driver or a libs release when initiating a new release, we follow a streamlined process inspired by the [Kubernetes Release Phases](https://github.com/kubernetes/sig-release/blob/master/releases/release_phases.md).

![release-process-overview](docs/img/release-process.svg "Code Freeze to Thaw")

### Preparation

Approximately 4 weeks before the release due date, maintainers evaluate pending features and determine which features shall be integrated into the upcoming release based on a set of criteria, such as, but not limited to:

 - Severity of the bug
 - Type of feature (nice-to-have refactor vs adding significant new capabilities or improves stability or performance)
 - Amount of user-facing changes
 - Non user-facing changes that can affect resource utilization (CPU, memory usage ...)
 - Amount of testing required to ensure stability and safety
 - TODO: add more criteria

In this phase, all enhancements expected to go into the release should be merged before the code freeze.

### Code freeze

Code freeze happens ~1 week before the release due date, and should last no more than ~5 days. Shorter freeze period are encouraged.

At this point, no new-feature PRs are allowed to be merged ([exceptions](#exceptions) apply). 

[Versioning](#versioning) rules must be double-checked and eventually enforced at this stage.

### Release branch

During the code freeze period, a *release branch* is created once the [release team](#release-team) ensures the code is in a good shape and reasonably no bugs are detected.

The naming convention for the release branch is `release/M.m.x`, where:
- `M.m` represents the _Major_ and _Minor_ [version](Versioning) numbers of the release.
- `x` is simply the character 'x', indicating that the branch encompasses the entire `M.m.x` release series.

For processes that involve both _drivers_ and _libs_ releases, only the _libs_ version number is reflected in the branch name.

When working with a release branch, adhere to the following rules:
- New commits should be added to the branch via cherry-picking.
- All tags within the release branch must maintain the same _major_ and _minor_ version as the release branch.
- Patch releases for the `M.m.x` series must be tagged directly within the respective `release/M.m.x` branch.
- If there's a need to bump the _major_ or _minor_ version (for either _libs_ or _drivers_) after the release branch is created, a new release branch should be created for the relevant component with the corresponding version.

For example, a `release/0.10.x` is created; it will host tags `0.10.0`, `0.10.1`, `0.10.2` and so on. `0.10.1` will be made of some cherry picked commits on top of `0.10.0`.

Once the release brach has been created:

 - A PR must be opened in our [test-infra](https://github.com/falcosecurity/test-infra/blob/master/config/config.yaml) repository to set the newly created branch as protected.

 - A release candidate tag should be created in the release branch for testing purposes.

 - Accurate testing is performed on the release candidate. Testing steps and criteria for passing each steps are outlined in [TBA doc]. It's highly recommended to use Falco as a consumer of the libs and drivers and perform automated and manual testing.

  - If necessary, PRs may be exceptionally merged on the `master` branch (see the [Exceptions](#exceptions) section below) as a last resort to unblock a release.
    In such a case, relevant commits must be cherry-picked and ported to the release branch, and then a new release candidate is tagged.
   
  - Not yet merged PRs must be moved to the subsequent milestone.

### Thaw

Once maintainers are trustful that the release candidate is in good shape, or after ~5 days from the code freeze, we enter the Thaw phase. 

From a technical perspective, this means that now the `master` and release branches diverge. 

Now, the release branch is git tagged with the targeted version.

From this point on:
- Only bug fix PRs are allowed to be merged in the release branch 
   - if any, the version patch number must be bumped  to git tag the release branch again.
- All kinds of PRs are allowed to be merged in the `master` branch again.

## Exceptions

Exceptions are allowed for compelling reasons. Notably:

- During the code freeze phase, PRs might be exceptionally merged:
   - to complete already planned features for that milestone
   - to fix bugs in core features or that affect stability, safety, performance
   - to address broken functionalities (including the possibility of reverting the previous behavior)
   - improvements to the testing suite or the CI if necessary to unblock the release
- Hotfixes releases can happen anytime and without following the full process. In such cases, patches are merged into the relevant release branch (or a release branch is created if needed), then a new version is git tagged, and the hotfix is directly released.

Exceptions to the [versioning rules](#versioning) are never allowed.

## Versioning

### Drivers versioning

The *driver version number* represents the build version of kernel-space drivers (i.e., the kernel module, the eBPF probe, and possibly any other kernel-space artifact).

**Requirements**

- The version MUST be a [SemVer 2.0](https://semver.org/spec/v2.0.0.html) compliant string.

- Since our driver APIs are assumed to be stable, the major version number MUST be equal to or greater than `1`.

- The version string MUST be suffixed with `+driver` to distinguish it from libs version numbers.

- To pick a new driver version number:

    1. The [API for user/kernel boundary](https://github.com/falcosecurity/libs/blob/master/proposals/20210818-driver-semver.md) is versioned in the source code. You MUST ensure the two files below have been updated by following the rules described in [driver/README.VERSION.md](https://github.com/falcosecurity/libs/blob/master/driver/README.VERSION.md):
        - [driver/API_VERSION](https://github.com/falcosecurity/libs/blob/master/driver/API_VERSION)
        - [driver/SCHEMA_VERSION](https://github.com/falcosecurity/libs/blob/master/driver/SCHEMA_VERSION)
    
        If not, open a PR to fix them.

    2. Compute the *driver version number* by strictly following the [Versioning Schema](https://github.com/falcosecurity/libs/blob/master/proposals/20220203-versioning-schema-amendment.md#drivers-artifacts) proposal's rules.

> _Note that `API_VERSION` and `SCHEMA_VERSION` are only used internally. On the other hand, only the **driver version number** will be used **to tag a new release**._

### Libs versioning

The *libs version number* represents a software version of the user-space libraries (i.e., libscap, libsinsp, and possibly any other further user-space library), and it is not tied to the drivers version numbering.

**Requirements**

- The version MUST be a [SemVer 2.0](https://semver.org/spec/v2.0.0.html) compliant string.

- Since our userspace APIs are not yet stable, the major version number MUST be `0` (see the SemVer section about the [initial development phase](https://semver.org/spec/v2.0.0.html#how-should-i-deal-with-revisions-in-the-0yz-initial-development-phase)).

- The [Plugin API](./userspace/libscap/engine/source_plugin/plugin_info.h) is versioned in the code and follow a semver-like numbering scheme. If any changes have been made to the Plugin API since the last release, you MUST ensure the Plugin API version is updated accordingly. If not, open a PR to fix it.
