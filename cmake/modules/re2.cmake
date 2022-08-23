#
# RE2
#
option(USE_BUNDLED_RE2 "Enable building of the bundled RE2" ${USE_BUNDLED_DEPS})

if(RE2_INCLUDE AND RE2_LIB)
	message(STATUS "Using re2: include: ${RE2_INCLUDE}, lib: ${RE2_LIB}")
elseif(NOT USE_BUNDLED_RE2)
	find_path(RE2_INCLUDE re2/re2.h PATH_SUFFIXES re2)
	find_library(RE2_LIB NAMES re2)
	if(RE2_INCLUDE AND RE2_LIB)
		message(STATUS "Found re2: include: ${RE2_INCLUDE}, lib: ${RE2_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system re2")
	endif()
else()
	set(RE2_SRC "${PROJECT_BINARY_DIR}/re2-prefix/src/re2")
	set(RE2_INCLUDE "${RE2_SRC}/usr/local/include")
    set(RE2_LIB "${RE2_SRC}/usr/local/lib/libre2.a")
	message(STATUS "Using bundled re2 in '${RE2_SRC}'")
	ExternalProject_Add(re2
			PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
			URL "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz"
			URL_HASH "SHA256=f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE} -j CXXFLAGS=-std=c++11
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${RE2_LIB}
			INSTALL_COMMAND ${CMD_MAKE} install DESTDIR=${RE2_SRC})
	install(FILES "${RE2_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps")
	install(DIRECTORY "${RE2_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps")
endif()

include_directories("${RE2_INCLUDE}")
