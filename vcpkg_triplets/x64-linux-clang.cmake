# Custom vcpkg triplet to build dependencies with clang on Linux

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CRT_LINKAGE dynamic)

if(PORT STREQUAL "civetweb")
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS -DCIVETWEB_CXX_ENABLE_LTO=OFF)
endif()
