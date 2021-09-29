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
	set(OPENSSL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl")
	set(OPENSSL_INSTALL_DIR "${OPENSSL_BUNDLE_DIR}/target")
	set(OPENSSL_INCLUDE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl/include")
	set(OPENSSL_LIBRARY_SSL "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
	set(OPENSSL_LIBRARY_CRYPTO "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")

	if(NOT TARGET openssl)
		message(STATUS "Using bundled openssl in '${OPENSSL_BUNDLE_DIR}'")

		ExternalProject_Add(openssl
			PREFIX "${PROJECT_BINARY_DIR}/openssl-prefix"
			URL "https://github.com/openssl/openssl/archive/OpenSSL_1_0_2u.tar.gz"
			URL_HASH "SHA256=82fa58e3f273c53128c6fe7e3635ec8cda1319a10ce1ad50a987c3df0deeef05"
			CONFIGURE_COMMAND ./config no-shared --prefix=${OPENSSL_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${OPENSSL_LIBRARY_SSL} ${OPENSSL_LIBRARY_CRYPTO}
			INSTALL_COMMAND ${CMD_MAKE} install)
	endif()
endif()

include_directories("${OPENSSL_INCLUDE_DIR}")
