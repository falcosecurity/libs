include_directories("../../../common")
include_directories("../../")

add_executable(sinsp-debug
	sinsp_debug.cpp
)

target_link_libraries(sinsp-debug
	sinsp
)

if (EMSCRIPTEN)
	target_compile_options(sinsp-debug PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(sinsp-debug PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(sinsp-debug PRIVATE "-sALLOW_MEMORY_GROWTH=1")
	target_link_options(sinsp-debug PRIVATE "-sEXPORTED_FUNCTIONS=['_main','_htons','_ntohs']")
	# note(jasondellaluce): since we run tests with node, we need to add this
	# for reading from local capture files.
	target_link_options(sinsp-debug PRIVATE "-sNODERAWFS=1")
endif()

if (APPLE AND NOT MINIMAL_BUILD)
	# Needed when linking libcurl
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -framework Foundation -framework SystemConfiguration")
endif()
