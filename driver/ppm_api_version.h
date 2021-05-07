#ifndef PPM_API_VERSION_H
#define PPM_API_VERSION_H

/*
 * API version component macros
 *
 * The version is a single uint64_t, structured as follows:
 * bit 63: unused (so the version number is always positive)
 * bits 44-62: major version
 * bits 24-43: minor version
 * bits 0-23: patch version
 */

/* extract components from an API version number */
#define PPM_API_VERSION_MAJOR(ver) ((((ver) >> 44)) & (((1 << 19) - 1)))
#define PPM_API_VERSION_MINOR(ver) (((ver) >> 24) & (((1 << 20) - 1)))
#define PPM_API_VERSION_PATCH(ver) (((ver) & ((1 << 24) - 1)))

/* build an API version number from components */
#define PPM_API_VERSION(major, minor, patch) \
	(((major) & (((1ULL << 19) - 1) << 44)) | \
	((minor) & (((1ULL << 20) - 1) << 24)) | \
	((major) & (((1ULL << 24) - 1))))

#define PPM_API_CURRENT_VERSION PPM_API_VERSION( \
	PPM_API_CURRENT_VERSION_MAJOR, \
	PPM_API_CURRENT_VERSION_MINOR, \
	PPM_API_CURRENT_VERSION_PATCH)

#define PPM_SCHEMA_CURRENT_VERSION PPM_API_VERSION( \
	PPM_SCHEMA_CURRENT_VERSION_MAJOR, \
	PPM_SCHEMA_CURRENT_VERSION_MINOR, \
	PPM_SCHEMA_CURRENT_VERSION_PATCH)

#define __PPM_STRINGIFY1(x) #x
#define __PPM_STRINGIFY(x) __PPM_STRINGIFY1(x)

#define PPM_API_CURRENT_VERSION_STRING \
	__PPM_STRINGIFY(PPM_API_CURRENT_VERSION_MAJOR) "." \
	__PPM_STRINGIFY(PPM_API_CURRENT_VERSION_MINOR) "." \
	__PPM_STRINGIFY(PPM_API_CURRENT_VERSION_PATCH)

#define PPM_SCHEMA_CURRENT_VERSION_STRING \
	__PPM_STRINGIFY(PPM_SCHEMA_CURRENT_VERSION_MAJOR) "." \
	__PPM_STRINGIFY(PPM_SCHEMA_CURRENT_VERSION_MINOR) "." \
	__PPM_STRINGIFY(PPM_SCHEMA_CURRENT_VERSION_PATCH)

#endif
