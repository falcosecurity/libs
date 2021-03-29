#
# libb64
#
option(USE_BUNDLED_B64 "Enable building of the bundled b64" ${USE_BUNDLED_DEPS})

if(B64_INCLUDE)
	# we already have b64
elseif(NOT USE_BUNDLED_B64)
	find_path(B64_INCLUDE NAMES b64/encode.h)
	find_library(B64_LIB NAMES b64)
	if(B64_INCLUDE AND B64_LIB)
		message(STATUS "Found b64: include: ${B64_INCLUDE}, lib: ${B64_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system b64")
	endif()
else()
	set(B64_SRC "${PROJECT_BINARY_DIR}/b64-prefix/src/b64")
	message(STATUS "Using bundled b64 in '${B64_SRC}'")
	set(B64_INCLUDE "${B64_SRC}/include")
	set(B64_LIB "${B64_SRC}/src/libb64.a")
	ExternalProject_Add(b64
		PREFIX "${PROJECT_BINARY_DIR}/b64-prefix"
		URL "https://github.com/libb64/libb64/archive/v1.2.1.tar.gz"
		URL_HASH "SHA256=d620e7caf3ed5f9c28d727fa799918ad3ef69c80975905646bb549a6019cdcbd"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${B64_LIB}
		INSTALL_COMMAND "")
endif()

include_directories("${B64_INCLUDE}")
