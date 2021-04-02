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
	set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include")
	set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf.a")
	set(PROTOC_LIB "${PROTOBUF_SRC}/target/lib/libprotoc.a")

	if(NOT TARGET protobuf)
		message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
		if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x")
			ExternalProject_Add(protobuf
				PREFIX "${PROJECT_BINARY_DIR}/protobuf-prefix"
				DEPENDS openssl zlib
				URL "http://download.sysdig.com/dependencies/protobuf-cpp-3.5.0.tar.gz"
				URL_MD5 "e4ba8284a407712168593e79e6555eb2"
				PATCH_COMMAND wget http://download.sysdig.com/dependencies/protobuf-3.5.0-s390x.patch && patch -p1 -i protobuf-3.5.0-s390x.patch
				# TODO what if using system zlib?
				CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
				COMMAND aclocal && automake
				BUILD_COMMAND ${CMD_MAKE}
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${PROTOC} ${PROTOC_LIB} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
				INSTALL_COMMAND make install)
		else()
			ExternalProject_Add(protobuf
				PREFIX "${PROJECT_BINARY_DIR}/protobuf-prefix"
				DEPENDS openssl zlib
				URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.13.0/protobuf-cpp-3.13.0.tar.gz"
				URL_HASH "SHA256=f8a547dfe143a9f61fadafba47fa6573713a33cb80909307c1502e26e1102298"
				# TODO what if using system zlib?
				CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
				BUILD_COMMAND ${CMD_MAKE}
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${PROTOC} ${PROTOC_LIB} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
				INSTALL_COMMAND make install)
		endif()
	endif()
endif()

include_directories("${PROTOBUF_INCLUDE}")
