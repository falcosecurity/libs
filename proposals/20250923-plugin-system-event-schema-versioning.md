# Proposal for the introduction of Schema Version check in the Plugin System

## Summary

This proposal provides an event schema validation system related to events emitted by libscap, and consumed by plugins providing parsing and/or field extraction capabilities. This will ensure backward compatibility and clear error reporting for plugins that depend on specific Schema Versions.

## Motivation

The current Falco plugin system only checks the Plugin API version, but there is no check on the [SCHEMA_VERSION][3]. This means that there is no guarantee that a given plugin with parsing or field extraction capabilities works across Falco versions.

1. **Runtime Validation**: There's no mechanism for plugins consuming driver events to declare the required Schema Version
1. **Version Compatibility**: No way to enforce compatibility between plugins and the syscall events they consume

## Goals

- Implement a comprehensive event schema validation system for plugins
- Provide backward compatibility guarantees for schema evolution
- Enable runtime schema validation with clear error reporting
- Not breaking the existing plugin APIs (this should be additive)

## Non-Goals

- Providing a versioning system for the internal data format carried by the plugin event type (this is out of scope for this proposal)
- Provide version check for event sourcing plugins, this proposal only focuses on plugins consuming events. A future proposal may address this.

## Proposal

### 1. Required Schema Version declaration

The plugins should declare the required Schema Version in the following cases.

- field extraction capability, unless the plugin will only receive events of the plugin type
- event parsing capability, unless the plugin will only receive events of the plugin type

If the plugin does not declare a required Schema Version, it is assumed that it
is compatible with 3.0.0, the initial major version at the time the plugin
event schema validation is introduced.

The plugin API should be extended with a new optional function to declare the required schema
version.

```c
// New plugin API functions for schema management
typedef struct {
  ...
    //
    // Return the version of the minimum Schema Version required by this plugin.
    // Required: no
    // Arguments:
    //   s: the plugin state returned by init(). Can be NULL.
    // Return value: the Schema Version string, in the following format:
    //       "<major>.<minor>.<patch>", e.g. "4.0.0".
    //       If NULL is returned, the plugin is assumed to be compatible with
    //       Schema Version 3.0.0, i.e. the major version in use in the release
    //       predating the introduction of this check.
    //
    const char* (*get_required_schema_version)(ss_plugin_t* s);
} plugin_api;
```

### 2. Runtime Schema Validation

When a plugin is loaded, the plugin loader should check if the plugin is actually consuming events of the expected Schema Version other than the plugin event type.

The check should be performed as follows:

**Determine if Schema Version check is needed:**
- If the plugin provides parsing capabilities (`CAP_PARSING`)
    - The check is needed if `get_parse_event_types` is not defined or provides an empty array and `m_parse_event_sources` contains `"syscall"`
    - The check is needed if `get_parse_event_types` provides an array containing at least an event code different from plugin type (i.e. 322)
    - No check is needed otherwise, because only plugin events are consumed
- If the plugin provides field extraction capabilities (`CAP_EXTRACTION`)
    - The check is needed if `get_extract_event_types` is not defined or provides an empty array and `m_extract_event_sources` contains `"syscall"`
    - The check is needed if `get_extract_event_types` provides an array containing at least a driver event
    - No check is needed otherwise, because only plugin events are consumed
- No check is needed if the plugin only provides event sourcing capabilities (`CAP_SOURCING`) or async capabilities (`CAP_ASYNC`)

### 3. Schema Version Compatibility Check

In case the check is required, the following logic is applied:

1. **Default Schema Version:**
   - If the plugin does not implement the `get_required_schema_version` function,
     it is assumed that it is compatible with the latest released Schema Version i.e. `3.0.0`

2. **Version string validation:**
   - If the plugin implements the `get_required_schema_version` function, the
     returned version string is parsed and validated
   - The version string must follow the semver format: `"<major>.<minor>.<patch>"`
   - If the version string is malformed or cannot be parsed, the plugin load fails with an error

3. **Version compatibility check:**
   - The event Schema Version in use in the current Falco libs version is compared with the required Schema Version declared by the plugin
   - **Major version incompatibility:** If the major versions differ, the plugin load fails
   - **Minor version incompatibility:** If the major versions match but the plugin requires a higher minor version than available, the plugin load fails
   - **Patch version:** Patch version differences are allowed (backward compatible)

4. **Error handling:**
   - **Malformed version string:** `"plugin provided an invalid required Schema Version: '<version>'"`
   - **Major version mismatch:** `"plugin required Schema Version '<version>' not compatible with the driver Schema Version '<version>': major versions disagree"`
   - **Minor version mismatch:** `"plugin required Schema Version '<version>' not compatible with the driver Schema Version '<version>': driver schema minor version is less than the requested one"`

### 4. Implementation Details

The implementation will require the following changes:

1. **Plugin API Extension:**
   - Add `get_required_schema_version` function pointer to the `plugin_api` struct
   - Place it at the end of the struct to maintain backward binary compatibility

2. **Plugin Loader Updates:**
   - Add symbol resolution for `get_required_schema_version` in `plugin_loader.c`
   - Implement Schema Version validation function similar to `plugin_check_required_api_version`

3. **Plugin Framework Integration:**
   - Add Schema Version check

4. **API Version Bump:**
   - This feature requires a minor plugin API version bump (e.g., from 3.11.0 to 3.12.0)
   - Existing plugins without the new function will default to Schema Version 3.0.0

## Risks and Mitigation

### Risks
- If we break driver event schema backward compatibility, introducing new major versions, we have to release new version of all the plugins consuming driver events even if they are not affected by the schema changes.

### Mitigation
- We will try to avoid breaking changes in the driver event schema as much as possible.

## Conclusion

This proposal aims to enhance the Falco plugin system by introducing a robust event Schema Version validation mechanism.
This will ensure that plugins remain compatible with the evolving event schema, providing a more reliable and maintainable plugin ecosystem.

The implementation follows the existing patterns in the codebase for API version checking, ensuring consistency and maintainability. The feature is designed to be backward compatible, with existing plugins defaulting to a safe Schema Version assumption.

### Benefits

- **Runtime Safety:** Prevents plugin crashes due to schema incompatibilities
- **Clear Error Messages:** Provides specific feedback about version mismatches
- **Backward Compatibility:** Existing plugins not consuming driver events continue to work without modification
- **Future-Proof:** Enables safe evolution of the event schema
- **Consistent API:** Follows established patterns in the plugin framework

## References

### Related Documentation

- **[Schema Version Doc][1]** - Comprehensive guide on when and how to increment API and Schema Versions
- **[Schema Version Checks][2]** - Automated CI checks for Schema Version bumps
- **[Schema Version][3]** - Current event schema version (`3.69.1`)

### Related Proposals

- **[Driver SemVer Proposal][4]** - API versioning for user/kernel boundary
- **[Versioning Schema Amendment][5]** - Dual versioning scheme for libs and drivers
- **[Versioning and Release Process][6]** - Original versioning and release strategy

### Implementation Context

- **[Plugin API Definition][7]** - Current plugin API structure where the new function would be added
- **[Plugin Loader][8]** - Plugin loading and validation logic
- **[Event Table][9]** - Event table

[1]: ../driver/README.VERSION.md
[2]: ../.github/workflows/driver-schema-version.yml
[3]: ../driver/SCHEMA_VERSION
[4]: ../proposals/20210818-driver-semver.md
[5]: ../proposals/20220203-versioning-schema-amendment.md
[6]: ../proposals/20210524-versioning-and-release-of-the-libs-artifacts.md
[7]: ../userspace/plugin/plugin_api.h
[8]: ../userspace/plugin/plugin_loader.c
[9]: ../driver/event_table.c
