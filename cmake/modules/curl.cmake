#
# libcurl
#
option(USE_BUNDLED_CURL "Enable building of the bundled curl" ${USE_BUNDLED_DEPS})

include(openssl)

if(CURL_INCLUDE_DIR)
	# we already have curl
elseif(NOT USE_BUNDLED_CURL)
	find_package(CURL REQUIRED)
	message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIR}, lib: ${CURL_LIBRARIES}")
else()
	set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
	set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
	set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")

	if(NOT USE_BUNDLED_OPENSSL)
		set(CURL_SSL_OPTION "--with-ssl")
	else()
		set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
		message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
		message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")
	endif()

	if(NOT TARGET curl)
		ExternalProject_Add(
			curl
			PREFIX "${PROJECT_BINARY_DIR}/curl-prefix"
			DEPENDS openssl zlib
			# START CHANGE for CVE-2017-8816, CVE-2017-8817, CVE-2017-8818, CVE-2018-1000007
			URL "https://github.com/curl/curl/releases/download/curl-7_77_0/curl-7.77.0.tar.bz2"
			URL_HASH "SHA256=6c0c28868cb82593859fc43b9c8fdb769314c855c05cf1b56b023acf855df8ea"
			# END CHANGE for CVE-2017-8816, CVE-2017-8817, CVE-2017-8818, CVE-2018-1000007
			CONFIGURE_COMMAND
			./configure
			${CURL_SSL_OPTION}
			--disable-shared
			--enable-optimize
			--disable-curldebug
			--disable-rt
			--enable-http
			--disable-ftp
			--disable-file
			--disable-ldap
			--disable-ldaps
			--disable-rtsp
			--disable-telnet
			--disable-tftp
			--disable-pop3
			--disable-imap
			--disable-smb
			--disable-smtp
			--disable-gopher
			--disable-sspi
			--disable-ntlm-wb
			--disable-tls-srp
			--without-winssl
			--without-darwinssl
			--without-polarssl
			--without-cyassl
			--without-nss
			--without-axtls
			--without-ca-path
			--without-ca-bundle
			--without-libmetalink
			--without-librtmp
			--without-winidn
			--without-libidn2
			--without-libpsl
			--without-nghttp2
			--without-libssh2
			--disable-threaded-resolver
			--without-brotli
			--without-zstd
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CURL_LIBRARIES}
			INSTALL_COMMAND "")
	endif()
endif()

include_directories("${CURL_INCLUDE_DIR}")
