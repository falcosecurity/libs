#
# jq
#
option(USE_BUNDLED_JQ "Enable building of the bundled jq" ${USE_BUNDLED_DEPS})

if(JQ_INCLUDE)
	# we already have jq
elseif(NOT USE_BUNDLED_JQ)
	find_path(JQ_INCLUDE jq.h PATH_SUFFIXES jq)
	find_library(JQ_LIB NAMES jq)
	if(JQ_INCLUDE AND JQ_LIB)
		message(STATUS "Found jq: include: ${JQ_INCLUDE}, lib: ${JQ_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system jq")
	endif()
else()
	set(JQ_SRC "${PROJECT_BINARY_DIR}/jq-prefix/src/jq")
	message(STATUS "Using bundled jq in '${JQ_SRC}'")
	set(JQ_INCLUDE "${JQ_SRC}/target/include")
	set(JQ_INSTALL_DIR "${JQ_SRC}/target")
	set(JQ_LIB "${JQ_INSTALL_DIR}/lib/libjq.a")
	set(ONIGURUMA_LIB "${JQ_INSTALL_DIR}/lib/libonig.a")

	if(NOT TARGET jq)
		message(STATUS "Bundled jq: include: ${JQ_INCLUDE}, lib: ${JQ_LIB}")

		# Why we mirror jq here?
		#
		# In their readme, jq claims that you don't have
		# to do autoreconf -fi when downloading a released tarball.
		#
		# However, they forgot to push the released makefiles
		# into their release tarbal.
		#
		# For this reason, we have to mirror their release after
		# doing the configuration ourselves.
		#
		# This is needed because many distros do not ship the right
		# version of autoreconf, making virtually impossible to build libs on them.
		# Read more about it here:
		#   https://github.com/stedolan/jq/issues/2061#issuecomment-593445920
		ExternalProject_Add(
			jq
			PREFIX "${PROJECT_BINARY_DIR}/jq-prefix"
			URL "https://download.falco.org/dependencies/jq-1.6.tar.gz"
			URL_HASH "SHA256=787518068c35e244334cc79b8e56b60dbab352dff175b7f04a94f662b540bfd9"
			CONFIGURE_COMMAND ./configure --disable-maintainer-mode --enable-all-static --disable-dependency-tracking --with-oniguruma=builtin --prefix=${JQ_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE} LDFLAGS=-all-static
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${JQ_LIB} ${ONIGURUMA_LIB}
			INSTALL_COMMAND ${CMD_MAKE} install)
	endif()
endif()

include_directories("${JQ_INCLUDE}")
