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
	include(openssl)
	include(zlib)

	set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
	set(PROTOC "${PROTOBUF_SRC}/target/bin/protoc")
	set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include/")
	set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf.a")
	set(PROTOC_LIB "${PROTOBUF_SRC}/target/lib/libprotoc.a")
	set(PROTOBUF_INSTALL_DIR "${PROTOBUF_SRC}/target")

	if(NOT TARGET protobuf)
		message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
		ExternalProject_Add(protobuf
			PREFIX "${PROJECT_BINARY_DIR}/protobuf-prefix"
			DEPENDS openssl zlib
			URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-cpp-3.17.3.tar.gz"
			URL_HASH "SHA256=51cec99f108b83422b7af1170afd7aeb2dd77d2bcbb7b6bad1f92509e9ccf8cb"
			# TODO what if using system zlib?
			CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --disable-shared --enable-static --prefix=${PROTOBUF_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
			INSTALL_COMMAND make install)
		install(FILES "${PROTOBUF_LIB}" DESTINATION "./lib/${LIBS_PACKAGE_NAME}/")
		install(FILES "${PROTOC_LIB}" DESTINATION "./lib/${LIBS_PACKAGE_NAME}/")
		install(FILES "${PROTOC}" DESTINATION "./bin/${LIBS_PACKAGE_NAME}/")
		install(DIRECTORY "${PROTOBUF_INCLUDE}" DESTINATION "./include/${LIBS_PACKAGE_NAME}/")
	endif()
endif()

include_directories("${PROTOBUF_INCLUDE}")
