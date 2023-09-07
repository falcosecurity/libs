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
		set(PROTOBUF_CONFIGURE_FLAGS --enable-shared --disable-static)
	else()
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(PROTOBUF_CONFIGURE_FLAGS --disable-shared --enable-static)
	endif()
	include(zlib)

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
			DEPENDS zlib
			URL "https://github.com/protocolbuffers/protobuf/releases/download/v23.4/protobuf-23.4.tar.gz"
			URL_HASH "SHA256=a700a49470d301f1190a487a923b5095bf60f08f4ae4cac9f5f7c36883d17971"
			CMAKE_ARGS
				-DCMAKE_BUILD_TYPE=None
				-DCMAKE_INSTALL_PREFIX:PATH=${PROTOBUF_INSTALL_DIR}
				-Dprotobuf_BUILD_TESTS:BOOL=OFF
				-Dprotobuf_BUILD_SHARED_LIBS:BOOL=ON
				-Dprotobuf_BUILD_LIBPROTOC:BOOL=ON
				-Dprotobuf_ABSL_PROVIDER=package
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
		)
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
