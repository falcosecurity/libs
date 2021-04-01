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
	set(GRPC_LIB "${GRPC_SRC}-build/libgrpc_unsecure.a")
	set(GRPCPP_LIB "${GRPC_SRC}-build/libgrpc++_unsecure.a")
	set(GRPC_CPP_PLUGIN "${GRPC_SRC}-build/grpc_cpp_plugin")

	get_filename_component(PROTOC_DIR ${PROTOC} PATH)

	if(NOT TARGET grpc)
		message(STATUS "Found pkg-config executable: ${PKG_CONFIG_EXECUTABLE}")
		message(STATUS "Using bundled grpc in '${GRPC_SRC}'")

		ExternalProject_Add(grpc
			DEPENDS c-ares protobuf zlib
			PREFIX "${PROJECT_BINARY_DIR}/grpc-prefix"
			DEPENDS openssl protobuf c-ares zlib
			GIT_REPOSITORY https://github.com/grpc/grpc.git
			GIT_TAG v1.32.0
			GIT_SUBMODULES "third_party/abseil-cpp third_party/re2"
			INSTALL_COMMAND ""
			BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB} ${GRPC_CPP_PLUGIN}
			CMAKE_CACHE_ARGS
				-DgRPC_INSTALL:BOOL=OFF
				-DgRPC_BUILD_TESTS:BOOL=OFF
				-DgRPC_BUILD_CSHARP_EXT:BOOL=OFF
				-DgRPC_BUILD_GRPC_CPP_PLUGIN:BOOL=ON
				-DgRPC_BUILD_GRPC_CSHARP_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_NODE_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_PHP_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_PYTHON_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_RUBY_PLUGIN:BOOL=OFF
				-DgRPC_ABSL_PROVIDER:STRING=module
				-DgRPC_RE2_PROVIDER:STRING=module
				-DgRPC_PROTOBUF_PROVIDER:STRING=package
				-DProtobuf_DIR:PATH=${PROTOBUF_INCLUDE}
				-DProtobuf_INCLUDE_DIR:PATH=${PROTOBUF_INCLUDE}
				-DProtobuf_LIBRARY:PATH=${PROTOBUF_LIB}
				-DProtobuf_PROTOC_LIBRARY:PATH=${PROTOC_LIB}
				-DProtobuf_PROTOC_EXECUTABLE:PATH=${PROTOC}
				-DgRPC_ZLIB_PROVIDER:STRING=package
				-DZLIB_ROOT:STRING=${ZLIB_INCLUDE}
				-DgRPC_CARES_PROVIDER:STRING=package
				-Dc-ares_DIR:PATH=${CARES_SRC}
				-Dc-ares_INCLUDE_DIR:PATH=${CARES_INCLUDE}
				-Dc-ares_LIBRARY:PATH=${CARES_LIB}
				-DgRPC_SSL_PROVIDER:STRING=package
				-DOPENSSL_ROOT_DIR:PATH=${OPENSSL_BUNDLE_DIR}
		)
	endif()
endif()

include_directories("${GRPC_INCLUDE}")
