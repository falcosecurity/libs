# API version number

The file API_VERSION must contain a semver-like version number of the userspace<->kernel API. All other lines are ignored.

The version number should be bumped whenever necessary during the development and testing phases of the release cycle. A version bump represents a single change or an atomic group of changes, and so it can happen multiple times during the same development cycle. A given version bump must not group multiple changes happened sparsely during a given release cycle.

## When to increment

**major version**: increment when the driver API becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes)

Do *not* increment for patches that only add support for new kernels, without affecting already supported ones.

# Schema version number

The file SCHEMA_VERSION must contain a semver-like version number of the event schema. All other lines are ignored.

The version number should be bumped whenever necessary during the development and testing phases of the release cycle. A version bump represents a single change or an atomic group of changes, and so it can happen multiple times during the same development cycle. A given version bump must not group multiple changes happened sparsely during a given release cycle.

## When to increment

**major version**: increment when the schema becomes incompatible with previous userspace versions

**minor version**: increment when new features are added but existing features remain compatible (e.g. new event fields or new events)

**patch version**: increment when code changes don't break compatibility (e.g. bug fixes in filler code)
