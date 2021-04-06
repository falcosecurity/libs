option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})

if(GRPC_INCLUDE)
	# we already have grpc
elseif(NOT USE_BUNDLED_GRPC)
	find_path(GRPCXX_INCLUDE NAMES grpc++/grpc++.h)
	if(GRPCXX_INCLUDE)
		set(GRPC_INCLUDE ${GRPCXX_INCLUDE})
	else()
		find_path(GRPCPP_INCLUDE NAMES grpcpp/grpcpp.h)
		set(GRPC_INCLUDE ${GRPCPP_INCLUDE})
		add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
	endif()
	find_library(GRPC_LIB NAMES grpc_unsecure)
	find_library(GRPCPP_LIB NAMES grpc++_unsecure)
	if(GRPC_INCLUDE AND GRPC_LIB AND GRPCPP_LIB)
		message(STATUS "Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system grpc")
	endif()
	find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
	if(NOT GRPC_CPP_PLUGIN)
		message(FATAL_ERROR "System grpc_cpp_plugin not found")
	endif()
else()
	include(cares)
	include(protobuf)
	include(zlib)
	find_package(PkgConfig)
	if(NOT PKG_CONFIG_FOUND)
		message(FATAL_ERROR "pkg-config binary not found")
	endif()
	set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
	set(GRPC_INCLUDE "${GRPC_SRC}/include")
	set(GRPC_LIB "${GRPC_SRC}/libs/opt/libgrpc.a")
	set(GRPCPP_LIB "${GRPC_SRC}/libs/opt/libgrpc++.a")
	set(GRPC_CPP_PLUGIN "${GRPC_SRC}/bins/opt/grpc_cpp_plugin")

	get_filename_component(PROTOC_DIR ${PROTOC} PATH)

	if(NOT TARGET grpc)
		message(STATUS "Found pkg-config executable: ${PKG_CONFIG_EXECUTABLE}")
		message(STATUS "Using bundled grpc in '${GRPC_SRC}'")

		ExternalProject_Add(grpc
			PREFIX "${PROJECT_BINARY_DIR}/grpc-prefix"
			DEPENDS openssl protobuf c-ares zlib
			GIT_REPOSITORY https://github.com/grpc/grpc.git
			GIT_TAG v1.32.0
			GIT_SUBMODULES "third_party/abseil-cpp third_party/re2"
			INSTALL_COMMAND ""
			CONFIGURE_COMMAND ""
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB}
			BUILD_COMMAND
				CFLAGS=-Wno-implicit-fallthrough
				PATH=${PROTOC_DIR}:$ENV{PATH}
				PKG_CONFIG_PATH=${PROTOBUF_SRC}:${CARES_SRC}:${OPENSSL_BUNDLE_DIR}
				HAS_SYSTEM_ZLIB=true
				HAS_SYSTEM_PROTOBUF=true
				HAS_SYSTEM_CARES=true
				HAS_EMBEDDED_OPENSSL_ALPN=false
				HAS_SYSTEM_OPENSSL_ALPN=true
				LDFLAGS=-L${PROTOBUF_SRC}/target/lib
				LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH}:${PROTOBUF_SRC}/target/lib:${CARES_SRC}/target/lib
				make static_c static_cxx grpc_cpp_plugin
		)
	endif()
endif()

include_directories("${GRPC_INCLUDE}")
