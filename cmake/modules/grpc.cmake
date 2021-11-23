option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})

if(GRPC_INCLUDE)
	# we already have grpc
	return()
endif()

# fixme(leogr,fededp): this workaround is required to inject the missing deps (built by gRCP cmakefiles)
# into target_link_libraries later
# note: the list below is manually generated starting from the output of pkg-config --libs grpc++
# note2: we don't want to depend upon pkg-config
set(GRPC_LIBRARIES "")
macro(push_grpc_dep module path)
	if(${GRPC_FROM_SYSTEM})
		find_library(GRPC_DEP NAMES ${module})
		if(NOT GRPC_DEP)
			message(FATAL_ERROR "Couldn't find ${module}")
		endif()
	else()
		# We are building the library ourselves during ExternalProject_Add evaluation
		set(GRPC_DEP ${path}/lib${module}.a)
	endif()
	list(APPEND GRPC_LIBRARIES "${GRPC_DEP}")
endmacro()

function(fill_grpc_deps GRPC_FROM_SYSTEM)
	push_grpc_dep(gpr "${GRPC_SRC}")
	push_grpc_dep(grpc "${GRPC_SRC}")
	push_grpc_dep(grpc++ "${GRPC_SRC}")
	push_grpc_dep(address_sorting "${GRPC_SRC}")
	push_grpc_dep(re2 "${GRPC_SRC}/third_party/re2/")
	push_grpc_dep(upb "${GRPC_SRC}")
	push_grpc_dep(absl_hash "${GRPC_SRC}/third_party/abseil-cpp/absl/hash/")
	push_grpc_dep(absl_city "${GRPC_SRC}/third_party/abseil-cpp/absl/hash/")
	push_grpc_dep(absl_wyhash "${GRPC_SRC}/third_party/abseil-cpp/absl/hash/")
	push_grpc_dep(absl_raw_hash_set "${GRPC_SRC}/third_party/abseil-cpp/absl/container/")
	push_grpc_dep(absl_hashtablez_sampler "${GRPC_SRC}/third_party/abseil-cpp/absl/container/")
	push_grpc_dep(absl_exponential_biased "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_statusor "${GRPC_SRC}/third_party/abseil-cpp/absl/status/")
	push_grpc_dep(absl_status "${GRPC_SRC}/third_party/abseil-cpp/absl/status/")
	push_grpc_dep(absl_cord "${GRPC_SRC}/third_party/abseil-cpp/absl/strings/")
	push_grpc_dep(absl_bad_optional_access "${GRPC_SRC}/third_party/abseil-cpp/absl/types/")
	push_grpc_dep(absl_bad_variant_access "${GRPC_SRC}/third_party/abseil-cpp/absl/types/")
	push_grpc_dep(absl_str_format_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/strings/")
	push_grpc_dep(absl_synchronization "${GRPC_SRC}/third_party/abseil-cpp/absl/synchronization/")
	push_grpc_dep(absl_graphcycles_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/synchronization/")
	push_grpc_dep(absl_stacktrace "${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/")
	push_grpc_dep(absl_symbolize "${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/")
	push_grpc_dep(absl_debugging_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/")
	push_grpc_dep(absl_demangle_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/debugging/")
	push_grpc_dep(absl_malloc_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_time "${GRPC_SRC}/third_party/abseil-cpp/absl/time/")
	push_grpc_dep(absl_civil_time "${GRPC_SRC}/third_party/abseil-cpp/absl/time/")
	push_grpc_dep(absl_strings "${GRPC_SRC}/third_party/abseil-cpp/absl/strings/")
	push_grpc_dep(absl_strings_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/strings/")
	push_grpc_dep(absl_base "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_spinlock_wait "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_int128 "${GRPC_SRC}/third_party/abseil-cpp/absl/numeric/")
	push_grpc_dep(absl_throw_delegate "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_raw_logging_internal "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_log_severity "${GRPC_SRC}/third_party/abseil-cpp/absl/base/")
	push_grpc_dep(absl_time_zone "${GRPC_SRC}/third_party/abseil-cpp/absl/time/")
endfunction()

if(NOT USE_BUNDLED_GRPC)
	find_path(GRPCXX_INCLUDE NAMES grpc++/grpc++.h)
	if(GRPCXX_INCLUDE)
		set(GRPC_INCLUDE ${GRPCXX_INCLUDE})
	else()
		find_path(GRPCPP_INCLUDE NAMES grpcpp/grpcpp.h)
		set(GRPC_INCLUDE ${GRPCPP_INCLUDE})
		add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
	endif()
	find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
	if(NOT GRPC_CPP_PLUGIN)
		message(FATAL_ERROR "System grpc_cpp_plugin not found")
	endif()

	fill_grpc_deps(TRUE)
	if(GRPC_INCLUDE)
		message(STATUS "Found grpc: include: ${GRPC_INCLUDE}")
	else()
		message(FATAL_ERROR "Couldn't find system grpc")
	endif()
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

		fill_grpc_deps(FALSE)
		
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
