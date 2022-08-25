#
# RE2
#
option(USE_BUNDLED_RE2 "Enable building of the bundled RE2" ${USE_BUNDLED_DEPS})

if(RE2_INCLUDE)
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
	set(RE2_INCLUDE "${RE2_SRC}/include")
	set(RE2_DIR "${RE2_SRC}/lib/cmake/re2")
	set(RE2_URL "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz")
	set(RE2_URL_HASH "SHA256=f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f")

	message(STATUS "Using bundled re2 in '${RE2_SRC}'")

	if(NOT WIN32)
		set(RE2_LIB "${RE2_SRC}/lib/libre2.a")
		ExternalProject_Add(re2
			PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
			URL "${RE2_URL}"
			URL_HASH "${RE2_URL_HASH}"
			BINARY_DIR "${PROJECT_BINARY_DIR}/re2-prefix/build"
			BUILD_BYPRODUCTS ${RE2_LIB}
			CMAKE_ARGS
				-DCMAKE_INSTALL_LIBDIR=lib
				-DRE2_BUILD_TESTING=OFF
				-DBUILD_SHARED_LIBS=OFF
				-DCMAKE_INSTALL_PREFIX=${RE2_SRC})
	else()
		set(RE2_LIB "${RE2_SRC}/lib/re2.lib")
		# see: https://cmake.org/cmake/help/latest/policy/CMP0091.html
		if(CMAKE_VERSION VERSION_LESS 3.15.0)
			ExternalProject_Add(re2
				PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
				URL "${RE2_URL}"
				URL_HASH "${RE2_URL_HASH}"
				BINARY_DIR "${PROJECT_BINARY_DIR}/re2-prefix/build"
				BUILD_BYPRODUCTS ${RE2_LIB}
				CMAKE_ARGS
					-DCMAKE_CXX_FLAGS_DEBUG="/MTd /Od"
					-DCMAKE_CXX_FLAGS_RELEASE="/MT"
					-DCMAKE_INSTALL_LIBDIR=lib
					-DRE2_BUILD_TESTING=OFF
					-DBUILD_SHARED_LIBS=OFF
					-DCMAKE_INSTALL_PREFIX=${RE2_SRC})
		else()
			ExternalProject_Add(re2
				PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
				URL "${RE2_URL}"
				URL_HASH "${RE2_URL_HASH}"
				BINARY_DIR "${PROJECT_BINARY_DIR}/re2-prefix/build"
				BUILD_BYPRODUCTS ${RE2_LIB}
				CMAKE_ARGS
					-DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW 
					-DCMAKE_MSVC_RUNTIME_LIBRARY:STRING=MultiThreaded$<$<CONFIG:Debug>:Debug>
					-DCMAKE_INSTALL_LIBDIR=lib
					-DRE2_BUILD_TESTING=OFF
					-DBUILD_SHARED_LIBS=OFF
					-DCMAKE_INSTALL_PREFIX=${RE2_SRC})
		endif()
	endif()

	install(FILES "${RE2_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps")
	install(DIRECTORY "${RE2_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps")
endif()

include_directories("${RE2_INCLUDE}")
