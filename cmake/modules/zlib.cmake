#
# zlib
#
option(USE_BUNDLED_ZLIB "Enable building of the bundled zlib" ${USE_BUNDLED_DEPS})

if(ZLIB_INCLUDE)
	# we already have zlib
elseif(NOT USE_BUNDLED_ZLIB)
	find_path(ZLIB_INCLUDE zlib.h PATH_SUFFIXES zlib)
	find_library(ZLIB_LIB NAMES z)
	if(ZLIB_INCLUDE AND ZLIB_LIB)
		message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system zlib")
	endif()
else()
	set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
	set(ZLIB_INCLUDE "${ZLIB_SRC}")
	if(NOT TARGET zlib)
		message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
		if(NOT WIN32)
			set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
			ExternalProject_Add(zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				URL "https://github.com/madler/zlib/archive/v1.2.11.tar.gz"
				URL_HASH "SHA256=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff"
				CONFIGURE_COMMAND ./configure --prefix=${ZLIB_SRC}
				BUILD_COMMAND ${CMD_MAKE}
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${ZLIB_LIB}
				INSTALL_COMMAND "")
		else()
			set(ZLIB_LIB "${ZLIB_SRC}/zdll.lib")
			ExternalProject_Add(zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				URL "https://github.com/madler/zlib/archive/v1.2.11.tar.gz"
				URL_HASH "SHA256=629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff"
				CONFIGURE_COMMAND ""
				BUILD_COMMAND nmake -f win32/Makefile.msc
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${ZLIB_LIB}
				INSTALL_COMMAND "")
		endif()
	endif()
endif()

include_directories(${ZLIB_INCLUDE})
