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
	if(BUILD_SHARED_LIBS)
		set(CARES_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(CARES_CPPFLAGS )
		set(CARES_STATIC_OPTION )
	else()
		set(CARES_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(CARES_CPPFLAGS -DCARES_STATICLIB)
		set(CARES_STATIC_OPTION --disable-shared)
	endif()
	set(CARES_SRC "${PROJECT_BINARY_DIR}/c-ares-prefix/src/c-ares")
	set(CARES_INCLUDE "${CARES_SRC}/target/include/")
	set(CARES_LIB "${CARES_SRC}/target/lib/libcares${CARES_LIB_SUFFIX}")
	set(CARES_INSTALL_DIR "${CARES_SRC}/target")

	if(NOT TARGET c-ares)
		message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
		ExternalProject_Add(c-ares
			PREFIX "${PROJECT_BINARY_DIR}/c-ares-prefix"
			URL "https://c-ares.haxx.se/download/c-ares-1.19.1.tar.gz"
			URL_HASH "SHA256=321700399b72ed0e037d0074c629e7741f6b2ec2dda92956abe3e9671d3e268e"
			CONFIGURE_COMMAND CPPFLAGS=${CARES_CPPFLAGS} ./configure ${CARES_STATIC_OPTION} --prefix=${CARES_INSTALL_DIR}
                        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
                        INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install)
		install(FILES "${CARES_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${CARES_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()

endif()

if(NOT TARGET c-ares)
	add_custom_target(c-ares)
endif()

include_directories("${CARES_INCLUDE}")
