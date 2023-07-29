#
# libbpf
#
option(USE_BUNDLED_LIBBPF "Enable building of the bundled libbpf" ${USE_BUNDLED_DEPS})

if(LIBBPF_INCLUDE)
    # we already have libbpf
elseif(NOT USE_BUNDLED_LIBBPF)
    find_path(LIBBPF_INCLUDE bpf/libbpf.h)
    find_library(LIBBPF_LIB NAMES bpf)
    if(LIBBPF_INCLUDE AND LIBBPF_LIB)
        message(STATUS "Found libbpf: include: ${LIBBPF_INCLUDE}, lib: ${LIBBPF_LIB}")
    else()
        message(FATAL_ERROR "Couldn't find system libbpf")
    endif()
else()
    set(LIBBPF_SRC "${PROJECT_BINARY_DIR}/libbpf-prefix/src")
    set(LIBBPF_BUILD_DIR "${LIBBPF_SRC}/libbpf-build")
    set(LIBBPF_INCLUDE "${LIBBPF_BUILD_DIR}/root/usr/include")
    set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/root/usr/lib64/libbpf.a")
    ExternalProject_Add(
        libbpf
        PREFIX "${PROJECT_BINARY_DIR}/libbpf-prefix"
        DEPENDS zlib libelf
        URL "https://github.com/libbpf/libbpf/archive/refs/tags/v1.2.2.tar.gz"
        URL_HASH
        "SHA256=32b0c41eabfbbe8e0c8aea784d7495387ff9171b5a338480a8fbaceb9da8d5e5"
        CONFIGURE_COMMAND mkdir -p build root
        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} BUILD_STATIC_ONLY=y OBJDIR=${LIBBPF_BUILD_DIR}/build DESTDIR=${LIBBPF_BUILD_DIR}/root NO_PKG_CONFIG=1 "EXTRA_CFLAGS=-fPIC -I${LIBELF_INCLUDE} -I${ZLIB_INCLUDE}" "LDFLAGS=-Wl,-Bstatic" "EXTRA_LDFLAGS=-L${LIBELF_SRC}/libelf/libelf -L${ZLIB_SRC}" -C ${LIBBPF_SRC}/libbpf/src install install_uapi_headers
        INSTALL_COMMAND ""
        UPDATE_COMMAND ""
    )
    message(STATUS "Using bundled libbpf: include'${LIBBPF_INCLUDE}', lib: ${LIBBPF_LIB}")
    install(FILES "${LIBBPF_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
    install(DIRECTORY "${LIBBPF_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
endif()

if(NOT TARGET libbpf)
    add_custom_target(libbpf)
endif()

include_directories(${LIBBPF_INCLUDE})
