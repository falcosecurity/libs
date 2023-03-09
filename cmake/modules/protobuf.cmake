option(USE_BUNDLED_PROTOBUF "Enable building of the bundled protobuf" ${USE_BUNDLED_DEPS})

if(PROTOBUF_INCLUDE)
	# we already have protobuf
elseif(NOT USE_BUNDLED_PROTOBUF)
	find_program(PROTOC NAMES protoc)
	find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
	find_library(PROTOBUF_LIB NAMES protobuf)
	if(PROTOC AND PROTOBUF_INCLUDE AND PROTOBUF_LIB)
		message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system protobuf")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(PROTOBUF_BUILD_SHARED ON)
	else()
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(PROTOBUF_BUILD_SHARED OFF)
	endif()

	set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
	set(PROTOC "${PROTOBUF_SRC}/target/bin/protoc")
	set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include/")
	set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf${PROTOBUF_LIB_SUFFIX}" CACHE PATH "Path to libprotobuf")
	set(PROTOC_LIB "${PROTOBUF_SRC}/target/lib/libprotoc${PROTOBUF_LIB_SUFFIX}")
	set(PROTOBUF_INSTALL_DIR "${PROTOBUF_SRC}/target")

	if(NOT TARGET protobuf)
		message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
		ExternalProject_Add(protobuf
			PREFIX "${PROJECT_BINARY_DIR}/protobuf-prefix"
			URL "https://github.com/protocolbuffers/protobuf/archive/v21.12/$pkgname-21.12.tar.gz"
			URL_HASH "SHA256=22fdaf641b31655d4b2297f9981fa5203b2866f8332d3c6333f6b0107bb320de"
			CMAKE_ARGS -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=${PROTOBUF_BUILD_SHARED} -Dprotobuf_WITH_ZLIB=OFF -DCMAKE_INSTALL_PREFIX=${PROTOBUF_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
			INSTALL_COMMAND make install)
		install(FILES "${PROTOBUF_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(FILES "${PROTOC_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${PROTOBUF_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET protobuf)
	add_custom_target(protobuf)
endif()

include_directories("${PROTOBUF_INCLUDE}")
