#
# Intel tbb
#
option(USE_BUNDLED_TBB "Enable building of the bundled tbb" ${USE_BUNDLED_DEPS})

if(TBB_INCLUDE_DIR)
	# we already have tbb
elseif(NOT USE_BUNDLED_TBB)
	find_path(TBB_INCLUDE_DIR tbb.h PATH_SUFFIXES tbb)
	find_library(TBB_LIB NAMES tbb)
	if(TBB_INCLUDE_DIR AND TBB_LIB)
		message(STATUS "Found tbb: include: ${TBB_INCLUDE_DIR}, lib: ${TBB_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system tbb")
	endif()
else()
	set(TBB_SRC "${PROJECT_BINARY_DIR}/tbb-prefix/src/tbb")
	set(TBB_INCLUDE_DIR "${TBB_SRC}/include/")
	set(TBB_LIB "${TBB_SRC}/lib_release/libtbb.a")
	if(NOT TARGET tbb)
		message(STATUS "Using bundled tbb in '${TBB_SRC}'")

		ExternalProject_Add(tbb
			PREFIX "${PROJECT_BINARY_DIR}/tbb-prefix"
			URL "https://github.com/oneapi-src/oneTBB/archive/refs/tags/v2021.8.0.tar.gz"
			URL_HASH "SHA256=eee380323bb7ce864355ed9431f85c43955faaae9e9bce35c62b372d7ffd9f8b"
			BUILD_IN_SOURCE 1
			BUILD_COMMAND ${CMD_MAKE} tbb
			CMAKE_ARGS
				-DBUILD_SHARED_LIBS=Off
				-DCMAKE_BUILD_TYPE=release
				-DTBB_OUTPUT_DIR_BASE=lib
			BUILD_BYPRODUCTS ${TBB_LIB}
			INSTALL_COMMAND "")
		install(FILES "${TBB_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${TBB_INCLUDE_DIR}/tbb" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET tbb)
	add_custom_target(tbb)
endif()

include_directories("${TBB_INCLUDE_DIR}")
