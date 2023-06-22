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
	set(ZLIB_HEADERS "")
	list(APPEND ZLIB_HEADERS
		"${ZLIB_INCLUDE}/crc32.h"
		"${ZLIB_INCLUDE}/deflate.h"
		"${ZLIB_INCLUDE}/gzguts.h"
		"${ZLIB_INCLUDE}/inffast.h"
		"${ZLIB_INCLUDE}/inffixed.h"
		"${ZLIB_INCLUDE}/inflate.h"
		"${ZLIB_INCLUDE}/inftrees.h"
		"${ZLIB_INCLUDE}/trees.h"
		"${ZLIB_INCLUDE}/zconf.h"
		"${ZLIB_INCLUDE}/zlib.h"
		"${ZLIB_INCLUDE}/zutil.h"
	)
	if(NOT TARGET zlib)
		message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
		if(NOT WIN32)
			if(BUILD_SHARED_LIBS)
				set(ZLIB_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
				set(ZLIB_CONFIGURE_FLAGS )
			else()
				set(ZLIB_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
				set(ZLIB_CONFIGURE_FLAGS "--static")
			endif()
			set(ZLIB_LIB "${ZLIB_SRC}/libz${ZLIB_LIB_SUFFIX}")
			ExternalProject_Add(zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				URL "https://github.com/madler/zlib/archive/v1.2.13.tar.gz"
				URL_HASH "SHA256=1525952a0a567581792613a9723333d7f8cc20b87a81f920fb8bc7e3f2251428"
				CONFIGURE_COMMAND ./configure --prefix=${ZLIB_SRC} ${ZLIB_CONFIGURE_FLAGS}
                                BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${ZLIB_LIB}
				INSTALL_COMMAND "")
			install(FILES "${ZLIB_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
					COMPONENT "libs-deps")
			install(FILES ${ZLIB_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/zlib"
					COMPONENT "libs-deps")
		else()
			set(ZLIB_LIB "${ZLIB_SRC}/zlib.lib")
			ExternalProject_Add(zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				URL "https://github.com/madler/zlib/archive/v1.2.13.tar.gz"
				URL_HASH "SHA256=1525952a0a567581792613a9723333d7f8cc20b87a81f920fb8bc7e3f2251428"
				CONFIGURE_COMMAND ""
				BUILD_COMMAND nmake -f win32/Makefile.msc
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${ZLIB_LIB}
				INSTALL_COMMAND "")
			install(FILES "${ZLIB_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
					COMPONENT "libs-deps")
			install(FILES ${ZLIB_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/zlib"
					COMPONENT "libs-deps")
		endif()
	endif()
endif()

if(NOT TARGET zlib)
	add_custom_target(zlib)
endif()

include_directories(${ZLIB_INCLUDE})
