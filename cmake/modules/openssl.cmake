#
# OpenSSL
#
option(USE_BUNDLED_OPENSSL "Enable building of the bundled OpenSSL" ${USE_BUNDLED_DEPS})

if(OPENSSL_INCLUDE_DIR)
	# we already have openssl
elseif(NOT USE_BUNDLED_OPENSSL)
	find_package(OpenSSL REQUIRED)
	message(STATUS "Found OpenSSL: include: ${OPENSSL_INCLUDE_DIR}, lib: ${OPENSSL_LIBRARIES}")
else()
	if(BUILD_SHARED_LIBS)
		set(OPENSSL_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(OPENSSL_SHARED_OPTION shared)
	else()
		set(OPENSSL_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(OPENSSL_SHARED_OPTION no-shared)
	endif()
	set(OPENSSL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl")
	set(OPENSSL_INSTALL_DIR "${OPENSSL_BUNDLE_DIR}/target")
	set(OPENSSL_INCLUDE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl/include/")
	set(OPENSSL_LIBRARY_SSL "${OPENSSL_INSTALL_DIR}/lib/libssl${OPENSSL_LIB_SUFFIX}")
	set(OPENSSL_LIBRARY_CRYPTO "${OPENSSL_INSTALL_DIR}/lib/libcrypto${OPENSSL_LIB_SUFFIX}")
 	set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARY_SSL} ${OPENSSL_LIBRARY_CRYPTO})

	if(NOT TARGET openssl)
		message(STATUS "Using bundled openssl in '${OPENSSL_BUNDLE_DIR}'")

		ExternalProject_Add(openssl
			PREFIX "${PROJECT_BINARY_DIR}/openssl-prefix"
			URL "https://github.com/openssl/openssl/archive/OpenSSL_1_1_1t.tar.gz"
			URL_HASH "SHA256=b1270f044e36452e15d1f2e18b702691a240b0445080282f2c7daaea8704ec5e"
			CONFIGURE_COMMAND ./config ${OPENSSL_SHARED_OPTION} --prefix=${OPENSSL_INSTALL_DIR}
                        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${OPENSSL_LIBRARY_SSL} ${OPENSSL_LIBRARY_CRYPTO}
                        INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install_sw)
		install(FILES "${OPENSSL_LIBRARY_SSL}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(FILES "${OPENSSL_LIBRARY_CRYPTO}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${OPENSSL_INCLUDE_DIR}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET openssl)
	add_custom_target(openssl)
endif()

include_directories("${OPENSSL_INCLUDE_DIR}")
