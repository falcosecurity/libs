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
		set(TBB_LIB_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
		set(TBB_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(TBB_LIB_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
		set(TBB_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()

	# lib name changes depending on platform and build type
	string(TOLOWER "${CMAKE_BUILD_TYPE}" _build_type)
	if(_build_type STREQUAL "debug")
		set(TBB_LIB_BASEDIR "${TBB_SRC}/lib_debug")
		if(NOT WIN32)
			set(TBB_LIB_BASENAME "tbb_debug")
		else()
			set(TBB_LIB_BASENAME "tbb12_debug")
		endif()
	else()
		set(TBB_LIB_BASEDIR "${TBB_SRC}/lib_${_build_type}")
		if(NOT WIN32)
			set(TBB_LIB_BASENAME "tbb")
		else()
			set(TBB_LIB_BASENAME "tbb12")
		endif()
	endif()	
	set(TBB_LIB "${TBB_LIB_BASEDIR}/${TBB_LIB_PREFIX}${TBB_LIB_BASENAME}${TBB_LIB_SUFFIX}")

	if(NOT TARGET tbb)
		message(STATUS "Using bundled tbb in '${TBB_SRC}'")
		set(TBB_SRC_URL "https://github.com/oneapi-src/oneTBB/archive/refs/tags/v2021.9.0.tar.gz")
		set(TBB_SRC_URL_HASH "SHA256=1ce48f34dada7837f510735ff1172f6e2c261b09460e3bf773b49791d247d24e")
		set(TBB_FLAGS "")
		if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
			# latest TBB has issues with GCC >= 12
			# see: https://github.com/oneapi-src/oneTBB/issues/843#issuecomment-1152646035
			set(TBB_FLAGS "-Wno-error=stringop-overflow")
		endif()

		if(NOT WIN32)	
			ExternalProject_Add(tbb
				PREFIX "${PROJECT_BINARY_DIR}/tbb-prefix"
				URL "${TBB_SRC_URL}"
				URL_HASH "${TBB_SRC_URL_HASH}"
				BUILD_IN_SOURCE 1
				BUILD_COMMAND ${CMAKE_COMMAND} --build . --target tbb
				CMAKE_ARGS
					-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
					-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
					-DTBB_OUTPUT_DIR_BASE=lib
					-DCMAKE_CXX_FLAGS="${TBB_FLAGS}"
				BUILD_BYPRODUCTS ${TBB_LIB}
				INSTALL_COMMAND "")
		else()
			# see: https://cmake.org/cmake/help/latest/policy/CMP0091.html
			if(CMAKE_VERSION VERSION_LESS 3.15.0)
				ExternalProject_Add(tbb
					PREFIX "${PROJECT_BINARY_DIR}/tbb-prefix"
					URL "${TBB_SRC_URL}"
					URL_HASH "${TBB_SRC_URL_HASH}"
					BUILD_IN_SOURCE 1
					BUILD_COMMAND ${CMAKE_COMMAND} --build . --target tbb --config ${CMAKE_BUILD_TYPE}
					CMAKE_ARGS
						-DCMAKE_CXX_FLAGS_DEBUG="/MTd /Od"
						-DCMAKE_CXX_FLAGS_RELEASE="/MT"
						-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
						-DTBB_OUTPUT_DIR_BASE=lib
						-DCMAKE_CXX_FLAGS="${TBB_FLAGS}"
					BUILD_BYPRODUCTS ${TBB_LIB}
					INSTALL_COMMAND "")
			else()
				ExternalProject_Add(tbb
					PREFIX "${PROJECT_BINARY_DIR}/tbb-prefix"
					URL "${TBB_SRC_URL}"
					URL_HASH "${TBB_SRC_URL_HASH}"
					BUILD_IN_SOURCE 1
					BUILD_COMMAND ${CMAKE_COMMAND} --build . --target tbb --config ${CMAKE_BUILD_TYPE}
					CMAKE_ARGS
						-DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW
						-DCMAKE_MSVC_RUNTIME_LIBRARY:STRING=MultiThreaded$<$<CONFIG:Debug>:Debug>
						-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
						-DTBB_OUTPUT_DIR_BASE=lib
						-DCMAKE_CXX_FLAGS="${TBB_FLAGS}"
					BUILD_BYPRODUCTS ${TBB_LIB}
					INSTALL_COMMAND "")
			endif()
		endif()

		install(DIRECTORY "${TBB_LIB_BASEDIR}/" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps"
				FILES_MATCHING PATTERN "${TBB_LIB_PREFIX}tbb*")
		install(DIRECTORY "${TBB_INCLUDE_DIR}/tbb" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET tbb)
	add_custom_target(tbb)
endif()

include_directories("${TBB_INCLUDE_DIR}")
