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
	if(BUILD_SHARED_LIBS)
		set(TBB_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(TBB_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	set(TBB_LIB "${TBB_SRC}/lib_release/libtbb${TBB_LIB_SUFFIX}")
	if(NOT TARGET tbb)
		message(STATUS "Using bundled tbb in '${TBB_SRC}'")
		set(TBB_FLAGS "")
		if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
			# latest TBB has issues with GCC >= 12
			# see: https://github.com/oneapi-src/oneTBB/issues/843#issuecomment-1152646035
			set(TBB_FLAGS "-Wno-error=stringop-overflow")
		endif()
		ExternalProject_Add(tbb
			PREFIX "${PROJECT_BINARY_DIR}/tbb-prefix"
			URL "https://github.com/oneapi-src/oneTBB/archive/refs/tags/v2021.8.0.tar.gz"
			URL_HASH "SHA256=eee380323bb7ce864355ed9431f85c43955faaae9e9bce35c62b372d7ffd9f8b"
			# CONFIGURE_COMMAND ""
			BUILD_IN_SOURCE 1
			BUILD_COMMAND ${CMAKE_COMMAND} --build . --target tbb
			CMAKE_ARGS
				-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
				-DCMAKE_BUILD_TYPE=release
				-DTBB_OUTPUT_DIR_BASE=lib
				-DCMAKE_CXX_FLAGS="${TBB_FLAGS}"
			BUILD_BYPRODUCTS ${TBB_LIB}
			INSTALL_COMMAND "")
		install(DIRECTORY ${TBB_SRC}/lib_release/ DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps"
				FILES_MATCHING PATTERN "libtbb*")
		install(DIRECTORY "${TBB_INCLUDE_DIR}/tbb" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET tbb)
	add_custom_target(tbb)
endif()

include_directories("${TBB_INCLUDE_DIR}")
