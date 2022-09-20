#
# Abseil
#
option(USE_BUNDLED_ABSEIL "Enable building of the bundled abseil" ${USE_BUNDLED_DEPS})

if(ABSEIL_INCLUDE_DIR)
	# we already have abseil
elseif(NOT USE_BUNDLED_ABSEIL)
	find_path(ABSEIL_INCLUDE_DIR absl/base/options.h PATH_SUFFIXES abseil)
	find_library(ABSEIL_LIB NAMES abseil)
	if(ABSEIL_INCLUDE_DIR AND ABSEIL_LIB)
		message(STATUS "Found abseil: include: ${ABSEIL_INCLUDE_DIR}, lib: ${ABSEIL_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system abseil")
	endif()
else()
	set(ABSEIL_SRC "${PROJECT_BINARY_DIR}/abseil-prefix/src/abseil")
	set(ABSEIL_INCLUDE_DIR "${ABSEIL_SRC}/include/")
	set(ABSEIL_LIB "${ABSEIL_SRC}/build/lib_release/libabseil.a")
	if(NOT TARGET abseil)
		message(STATUS "Using bundled abseil in '${ABSEIL_SRC}'")

		ExternalProject_Add(abseil
			PREFIX "${PROJECT_BINARY_DIR}/abseil-prefix"
			URL "https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.tar.gz"
			URL_HASH "SHA256=91ac87d30cc6d79f9ab974c51874a704de9c2647c40f6932597329a282217ba8"
			INSTALL_COMMAND "")
		install(FILES "${ABSEIL_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${ABSEIL_INCLUDE_DIR}/abseil" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

include_directories("${ABSEIL_INCLUDE_DIR}")
