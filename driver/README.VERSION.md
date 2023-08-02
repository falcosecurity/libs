# API version number

The file API_VERSION must contain a semver-like version number of the userspace<->kernel API. All other lines are ignored.

The version number must be incremented every time and only when a single change or an atomic group of changes - which meet the criteria described in the _When to Increment_ section below - is included in the `master` branch. Thus, a version bump can occur multiple times during the development and testing phases of a given release cycle. A given version bump must not group multiple changes that occurred sporadically during the release cycle.

## When to increment

**major version**: increment when the driver API becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes)

Do *not* increment for patches that only add support for new kernels, without affecting already supported ones.

# Schema version number

The file SCHEMA_VERSION must contain a semver-like version number of the event schema. All other lines are ignored.

The version number must be incremented every time and only when a single change or an atomic group of changes - which meet the criteria described in the _When to Increment_ section below - is included in the `master` branch. Thus, a version bump can occur multiple times during the development and testing phases of a given release cycle. A given version bump must not group multiple changes that occurred sporadically during the release cycle.

## When to increment

**major version**: increment when the schema becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible (e.g. new event fields or new events)

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes in filler code)
