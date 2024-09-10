include(ExternalProject)

add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})

install(
	DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test
	COMPONENT tests
)

execute_process(
	COMMAND "uname" "-m"
	OUTPUT_VARIABLE ARCH
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_executable(forking_main_thread_exit forking_main_thread_exit.c)
target_link_libraries(forking_main_thread_exit pthread)
add_dependencies(libsinsp_e2e_tests forking_main_thread_exit)

add_executable(forking_nested forking_nested.c)
target_link_libraries(forking_nested pthread)
add_dependencies(libsinsp_e2e_tests forking_nested)

add_executable(chname chname.cpp)
target_link_libraries(chname pthread)
add_dependencies(libsinsp_e2e_tests chname)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
	add_executable(execve execve.c)
	add_dependencies(libsinsp_e2e_tests execve)

	# Build 32-bit tests only for architectures where that is supported
	if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
		add_executable(execve32 execve.c)
		set_target_properties(execve32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
		add_dependencies(libsinsp_e2e_tests execve32)
	endif()
endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
