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
	set(CARES_INCLUDE "${CARES_SRC}/target/include/")
	set(CARES_LIB "${CARES_SRC}/target/lib/libcares.a")
	set(CARES_INSTALL_DIR "${CARES_SRC}/target")

	if(NOT TARGET c-ares)
		message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
		ExternalProject_Add(c-ares
			PREFIX "${PROJECT_BINARY_DIR}/c-ares-prefix"
			URL "https://c-ares.haxx.se/download/c-ares-1.18.1.tar.gz"
			URL_HASH "SHA256=1a7d52a8a84a9fbffb1be9133c0f6e17217d91ea5a6fa61f6b4729cda78ebbcf"
			CONFIGURE_COMMAND CPPFLAGS=-DCARES_STATICLIB ./configure --disable-shared --prefix=${CARES_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
			INSTALL_COMMAND ${CMD_MAKE} install)
		install(FILES "${CARES_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${CARES_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
	
endif()

include_directories("${CARES_INCLUDE}")
