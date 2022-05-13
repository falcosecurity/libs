include(protobuf)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(scap_engine_gvisor STATIC
    pkg/sentry/seccheck/points/syscall.pb.cc
    pkg/sentry/seccheck/points/common.pb.cc
    pkg/sentry/seccheck/points/container.pb.cc
    pkg/sentry/seccheck/points/sentry.pb.cc
    parsers.cpp
)

if(USE_BUNDLED_PROTOBUF)
    add_dependencies(scap_engine_gvisor protobuf)
endif()

target_link_libraries(scap_engine_gvisor ${PROTOBUF_LIB} scap)

add_custom_command(
    OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.h
    COMMENT "Generate gVisor protobuf definitions"
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/common.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/container.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/sentry.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/syscall.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

