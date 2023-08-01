include(protobuf)
include(jsoncpp)

include_directories(${LIBSCAP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR} ${JSONCPP_INCLUDE})

find_package(Threads)

set(scap_engine_gvisor_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/parsers.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/gvisor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/scap_gvisor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/scap_gvisor_platform.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/runsc.cpp
)

set(scap_engine_gvisor_generated_sources
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.cc
)

set(scap_engine_gvisor_generated_headers
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.h
)

add_custom_command(
    OUTPUT ${scap_engine_gvisor_generated_sources} ${scap_engine_gvisor_generated_headers}
    COMMENT "Generate gVisor protobuf definitions"
    DEPENDS protobuf
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/common.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/common.proto
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/container.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/container.proto
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/sentry.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/sentry.proto
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/syscall.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/syscall.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

if(USE_BUNDLED_JSONCPP)
    add_dependencies(scap jsoncpp)
endif()

if (BUILD_SHARED_LIBS)
    # Trying to build a shared scap_engine_gvisor will result in circular
    # dependencies, so just add our sources to scap.
    # Additionally, the GENERATED property doesn't propogate across directories,
    # so enforce our dependency chain using an object library.
    # https://gitlab.kitware.com/cmake/cmake/-/issues/18399
    add_library(scap_engine_gvisor_o OBJECT
        ${scap_engine_gvisor_sources}
        ${scap_engine_gvisor_generated_sources}
    )
    set_property(TARGET scap_engine_gvisor_o PROPERTY POSITION_INDEPENDENT_CODE ON)

    add_dependencies(scap scap_engine_gvisor_o)
    target_sources(scap PRIVATE $<TARGET_OBJECTS:scap_engine_gvisor_o>)
else()
    add_library(scap_engine_gvisor
        ${scap_engine_gvisor_sources}
        ${scap_engine_gvisor_generated_sources}
    )

    target_link_libraries(scap_engine_gvisor
        ${CMAKE_THREAD_LIBS_INIT}
        ${PROTOBUF_LIB}
        ${JSONCPP_LIB}
        scap
        scap_platform_util
        scap_error
    )
    set_scap_target_properties(scap_engine_gvisor)
endif()
