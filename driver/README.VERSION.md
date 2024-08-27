# Driver internal versioning

This document explains how and when the internal [*API version number*](#api-version-number) and the [*Schema version number*](#schema-version-number) must be incremented. They do not represent the driver version associated with a driver release. For more information about the driver version, see our [release process documentation](https://github.com/falcosecurity/libs/blob/master/release.md).

The version numbers described below must be incremented every time and only when a single change or an atomic group of changes - which meet the criteria described in the relative _When to Increment_ section below - is included in the `master` branch. Thus, a version bump can occur multiple times during the development and testing phases of a given release cycle. A given version bump must not group multiple changes that occurred sporadically during the release cycle.

Please, do *not* increment these versions for patches that solely address build issues on specific kernels (for example, newly supported kernels) without impacting others. In these instances, only the driver's version number must be bumped when the driver is released.

## API version number

The first line of [API_VERSION](API_VERSION) file contains a semver-like version number of the **userspace<->kernel API**. All other lines are ignored.

### When to increment

**major version**: increment when the driver API becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes)

## Schema version number

The first line of [SCHEMA_VERSION](SCHEMA_VERSION) file contains a semver-like version number of the **event schema**. All other lines are ignored.

### When to increment

**major version**: increment when the schema becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible (e.g. new event fields or new events)

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes in filler code)
