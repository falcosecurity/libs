option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})

if(GRPC_INCLUDE)
	# we already have grpc
elseif(NOT USE_BUNDLED_GRPC)
	# Fetch gRPC++ dependencies (gpr and grpc are deps of gRPC++)
	find_package(PkgConfig REQUIRED)
	# This will internally set GRPC_LIBRARIES
	pkg_check_modules(GRPC REQUIRED grpc++ QUIET)

	# handle /usr/include/grpc{++,pp}/
	find_path(GRPCPP_INCLUDE NAMES ${GRPC_INCLUDEDIR}/grpcpp/grpcpp.h)
	if (GRPCPP_INCLUDE)
		add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
	endif()

	message(STATUS "Found grpc: include: ${GRPC_INCLUDEDIR}")

	# Check cpp plugin
	find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
	if(NOT GRPC_CPP_PLUGIN)
		message(FATAL_ERROR "System grpc_cpp_plugin not found")
	endif()

	# This var is required by build system, see below usage
	set(GRPC_INCLUDE "${GRPC_INCLUDEDIR}")
else()
	include(cares)
	include(protobuf)
	include(zlib)
	include(openssl)
	set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
	set(GRPC_INSTALL_DIR "${GRPC_SRC}/target")
	set(GRPC_INCLUDE 
		"${GRPC_INSTALL_DIR}/include"
		"${GRPC_SRC}/third_party/abseil-cpp")
	set(GPR_LIB "${GRPC_SRC}/libgpr.a")
	set(GRPC_LIB "${GRPC_SRC}/libgrpc.a")
	set(GRPCPP_LIB "${GRPC_SRC}/libgrpc++.a")
	set(GRPC_CPP_PLUGIN "${GRPC_SRC}/grpc_cpp_plugin")

	get_filename_component(PROTOC_DIR ${PROTOC} PATH)

	if(NOT TARGET grpc)
		message(STATUS "Using bundled grpc in '${GRPC_SRC}'")

		# fixme(leogr): this workaround is required to inject the missing deps (built by gRCP cmakefiles)
		# into target_link_libraries later
		# note: the list below is manually generated starting from the output of pkg-config --libs grpc++
		set(GRPC_LIBRARIES "")
		list(APPEND GRPC_LIBRARIES
			"${GRPCPP_LIB}"
			"${GRPC_LIB}"
			"${GPR_LIB}"
			"${GRPC_SRC}/libaddress_sorting.a"
			"${GRPC_SRC}/third_party/re2/libre2.a"
			"${GRPC_SRC}/libupb.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/hash/libabsl_hash.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/hash/libabsl_city.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/hash/libabsl_wyhash.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/container/libabsl_raw_hash_set.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/container/libabsl_hashtablez_sampler.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_exponential_biased.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/status/libabsl_statusor.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/status/libabsl_status.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_cord.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/types/libabsl_bad_optional_access.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/types/libabsl_bad_variant_access.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_str_format_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/synchronization/libabsl_synchronization.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/synchronization/libabsl_graphcycles_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_stacktrace.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_symbolize.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_debugging_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/libabsl_demangle_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_malloc_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/time/libabsl_time.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/time/libabsl_civil_time.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_strings.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/strings/libabsl_strings_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_base.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_spinlock_wait.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/numeric/libabsl_int128.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_throw_delegate.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_raw_logging_internal.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/base/libabsl_log_severity.a"
			"${GRPC_SRC}/third_party/abseil-cpp/absl/time/libabsl_time_zone.a"
		)
		
		ExternalProject_Add(grpc
			PREFIX "${PROJECT_BINARY_DIR}/grpc-prefix"
			DEPENDS openssl protobuf c-ares zlib
			GIT_REPOSITORY https://github.com/grpc/grpc.git
			GIT_TAG v1.38.1
			GIT_SUBMODULES "third_party/abseil-cpp third_party/re2"
			CMAKE_CACHE_ARGS
				-DCMAKE_INSTALL_PREFIX:PATH=${GRPC_INSTALL_DIR}
				-DCMAKE_BUILD_TYPE:STRING=Release
				-DgRPC_INSTALL:BOOL=OFF
				# disable unused stuff
				-DgRPC_BUILD_TESTS:BOOL=OFF
				-DgRPC_BUILD_CSHARP_EXT:BOOL=OFF
				-DgRPC_BUILD_GRPC_CSHARP_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_NODE_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_PHP_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_PYTHON_PLUGIN:BOOL=OFF
				-DgRPC_BUILD_GRPC_RUBY_PLUGIN:BOOL=OFF
				# deps provided by us
				# https://github.com/grpc/grpc/blob/v1.32.0/cmake/modules/Findc-ares.cmake
				-DgRPC_CARES_PROVIDER:STRING=package
				-Dc-ares_DIR:PATH=${CARES_SRC}
				-Dc-ares_INCLUDE_DIR:PATH=${CARES_INCLUDE}
				-Dc-ares_LIBRARY:PATH=${CARES_LIB}
				# https://cmake.org/cmake/help/v3.6/module/FindProtobuf.html
				-DgRPC_PROTOBUF_PROVIDER:STRING=package
				-DCMAKE_CXX_FLAGS:STRING=-I${PROTOBUF_INCLUDE}
				-DProtobuf_INCLUDE_DIR:PATH=${PROTOBUF_INCLUDE}
				-DProtobuf_LIBRARY:PATH=${PROTOBUF_LIB}
				-DProtobuf_PROTOC_LIBRARY:PATH=${PROTOC_LIB}
				-DProtobuf_PROTOC_EXECUTABLE:PATH=${PROTOC}
				# https://cmake.org/cmake/help/v3.6/module/FindOpenSSL.html
				-DgRPC_SSL_PROVIDER:STRING=package
				-DOPENSSL_ROOT_DIR:PATH=${OPENSSL_INSTALL_DIR}
				-DOPENSSL_USE_STATIC_LIBS:BOOL=TRUE
				# https://cmake.org/cmake/help/v3.6/module/FindZLIB.html
				-DgRPC_ZLIB_PROVIDER:STRING=package
				-DZLIB_ROOT:STRING=${ZLIB_SRC}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB} ${GPR_LIB} ${GRPC_LIBRARIES}
			# Keep installation files into the local ${GRPC_INSTALL_DIR} 
			# since here is the case when we are embedding gRPC
			INSTALL_COMMAND DESTDIR= ${CMD_MAKE} install
		)
	endif()
endif()

include_directories("${GRPC_INCLUDE}")
