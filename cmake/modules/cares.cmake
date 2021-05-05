option(USE_BUNDLED_CARES "Enable building of the bundled c-ares" ${USE_BUNDLED_DEPS})

if(CARES_INCLUDE)
	# we already have c-ares
elseif(NOT USE_BUNDLED_CARES)
	find_path(CARES_INCLUDE NAMES cares/ares.h ares.h)
	find_library(CARES_LIB NAMES cares)
	if(CARES_INCLUDE AND CARES_LIB)
		message(STATUS "Found c-ares: include: ${CARES_INCLUDE}, lib: ${CARES_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system c-ares")
	endif()
else()
	set(CARES_SRC "${PROJECT_BINARY_DIR}/c-ares-prefix/src/c-ares")
	set(CARES_INCLUDE "${CARES_SRC}/target/include")
	set(CARES_LIB "${CARES_SRC}/target/lib/libcares.a")
	set(CARES_INSTALL_DIR "${CARES_SRC}/target")

	if(NOT TARGET c-ares)
		message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
		ExternalProject_Add(c-ares
			PREFIX "${PROJECT_BINARY_DIR}/c-ares-prefix"
			URL "https://c-ares.haxx.se/download/c-ares-1.15.0.tar.gz"
			URL_HASH "SHA256=6cdb97871f2930530c97deb7cf5c8fa4be5a0b02c7cea6e7c7667672a39d6852"
			CONFIGURE_COMMAND ./configure --prefix=${CARES_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
			INSTALL_COMMAND ${CMD_MAKE} install)
	endif()
endif()

include_directories("${CARES_INCLUDE}")
