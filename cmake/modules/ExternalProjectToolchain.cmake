include_guard()

function(falcosecurity_gnu_target_triplet out_var)
	set(triplet "")
	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
			set(triplet "x86_64-linux-gnu")
		elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
			set(triplet "aarch64-linux-gnu")
		endif()
	endif()

	set(${out_var} "${triplet}" PARENT_SCOPE)
endfunction()

function(falcosecurity_external_project_cmake_args out_var)
	set(args
		-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
		-DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}
		-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
	)

	foreach(
		var
		CMAKE_TOOLCHAIN_FILE
		CMAKE_C_COMPILER
		CMAKE_CXX_COMPILER
		CMAKE_ASM_COMPILER
		CMAKE_AR
		CMAKE_RANLIB
		CMAKE_STRIP
		CMAKE_FIND_ROOT_PATH
		CMAKE_FIND_ROOT_PATH_MODE_PROGRAM
		CMAKE_FIND_ROOT_PATH_MODE_LIBRARY
		CMAKE_FIND_ROOT_PATH_MODE_INCLUDE
		CMAKE_FIND_ROOT_PATH_MODE_PACKAGE
	)
		if(DEFINED ${var} AND NOT "${${var}}" STREQUAL "")
			list(APPEND args "-D${var}=${${var}}")
		endif()
	endforeach()

	set(${out_var} ${args} PARENT_SCOPE)
endfunction()

function(falcosecurity_external_project_env out_var)
	set(args env)

	if(DEFINED CMAKE_C_COMPILER AND NOT "${CMAKE_C_COMPILER}" STREQUAL "")
		list(APPEND args "CC=${CMAKE_C_COMPILER}")
	endif()
	if(DEFINED CMAKE_CXX_COMPILER AND NOT "${CMAKE_CXX_COMPILER}" STREQUAL "")
		list(APPEND args "CXX=${CMAKE_CXX_COMPILER}")
	endif()
	if(DEFINED CMAKE_AR AND NOT "${CMAKE_AR}" STREQUAL "")
		list(APPEND args "AR=${CMAKE_AR}")
	endif()
	if(DEFINED CMAKE_RANLIB AND NOT "${CMAKE_RANLIB}" STREQUAL "")
		list(APPEND args "RANLIB=${CMAKE_RANLIB}")
	endif()
	if(DEFINED CMAKE_STRIP AND NOT "${CMAKE_STRIP}" STREQUAL "")
		list(APPEND args "STRIP=${CMAKE_STRIP}")
	endif()

	falcosecurity_gnu_target_triplet(target_triplet)
	if(NOT "${target_triplet}" STREQUAL "")
		list(APPEND args "CHOST=${target_triplet}")
	endif()

	set(${out_var} ${args} PARENT_SCOPE)
endfunction()
