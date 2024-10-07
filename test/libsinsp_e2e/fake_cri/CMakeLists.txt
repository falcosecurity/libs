include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(NOT EXISTS ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.grpc.pb.cc)
	file(TOUCH ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.grpc.pb.cc
		 ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.pb.cc
	)
endif()

add_executable(
	fake_cri fake_cri.cpp ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.grpc.pb.cc
			 ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.pb.cc
)

include(protobuf)
include(grpc)
target_link_libraries(
	fake_cri
	PRIVATE "${GRPC_LIBRARIES}"
			"${GRPCPP_LIB}"
			"${GRPC_LIB}"
			"${GPR_LIB}"
			"${PROTOBUF_LIB}"
			"${CARES_LIB}"
			pthread
			sinsp
			rt
)

target_include_directories(fake_cri PRIVATE ${CMAKE_BINARY_DIR} ${PROTOBUF_INCLUDE})

file(GLOB PROTOS "*.pb")
foreach(FILENAME IN LISTS PROTOS)
	configure_file(${FILENAME} ${CMAKE_BINARY_DIR}/test/libsinsp_e2e/resources/ COPYONLY)
endforeach()
