#
# LuaJIT
#
option(USE_BUNDLED_LUAJIT "Enable building of the bundled LuaJIT" ${USE_BUNDLED_DEPS})

if(LUAJIT_INCLUDE)
	# we already have luajit
elseif(NOT USE_BUNDLED_LUAJIT)
	find_path(LUAJIT_INCLUDE luajit.h PATH_SUFFIXES luajit-2.0 luajit-2.1 luajit)
	find_library(LUAJIT_LIB NAMES luajit luajit-5.1)
	if(LUAJIT_INCLUDE AND LUAJIT_LIB)
		message(STATUS "Found LuaJIT: include: ${LUAJIT_INCLUDE}, lib: ${LUAJIT_LIB}")
	else()
		# alternatively try stock Lua
		find_package(Lua51)
		set(LUAJIT_LIB ${LUA_LIBRARY})
		set(LUAJIT_INCLUDE ${LUA_INCLUDE_DIR})

		if(NOT ${LUA51_FOUND})
			message(FATAL_ERROR "Couldn't find system LuaJIT or Lua")
		endif()
	endif()
else()
	set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
	set(LUAJIT_INCLUDE "${LUAJIT_SRC}/")

	if(NOT WIN32)
		set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
	else()
		set(LUAJIT_LIB "${LUAJIT_SRC}/lua51.lib")
	endif()

	if(NOT TARGET luajit)
		message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
		if(NOT WIN32)
			if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ppc64le")
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/moonjit/moonjit"
					GIT_TAG "2.1.2"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND ${CMD_MAKE}
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					UPDATE_COMMAND ""
					INSTALL_COMMAND "")
			elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x")
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/linux-on-ibm-z/LuaJIT.git"
					GIT_TAG "v2.1"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND ${CMD_MAKE}
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					UPDATE_COMMAND ""
					INSTALL_COMMAND "")
			elseif(APPLE)
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					URL "https://github.com/LuaJIT/LuaJIT/archive/v2.1.0-beta3.tar.gz"
					URL_HASH "SHA256=409f7fe570d3c16558e594421c47bdd130238323c9d6fd6c83dedd2aaeb082a8"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND make MACOSX_DEPLOYMENT_TARGET=10.14
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					INSTALL_COMMAND "")
			else()
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/LuaJIT/LuaJIT"
					GIT_TAG "f3c856915b4ce7ccd24341e8ac73e8a9fd934171"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND ${CMD_MAKE}
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					UPDATE_COMMAND ""
					INSTALL_COMMAND "")
			endif()
			install(FILES "${LUAJIT_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}/")
			install(DIRECTORY "${LUAJIT_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/"
				FILES_MATCHING PATTERN "*.h")
		else()
			ExternalProject_Add(luajit
				PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
				URL "https://github.com/LuaJIT/LuaJIT/archive/v2.1.0-beta3.tar.gz"
				URL_HASH "SHA256=409f7fe570d3c16558e594421c47bdd130238323c9d6fd6c83dedd2aaeb082a8"
				CONFIGURE_COMMAND ""
				BUILD_COMMAND msvcbuild.bat
				BUILD_BYPRODUCTS ${LUAJIT_LIB}
				BINARY_DIR "${LUAJIT_SRC}"
				INSTALL_COMMAND "")
		endif()
	endif()
endif()
include_directories("${LUAJIT_INCLUDE}")
