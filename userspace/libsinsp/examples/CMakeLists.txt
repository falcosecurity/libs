include_directories("../../../common")
include_directories("../../")

add_executable(sinsp-example
	util.cpp
	test.cpp
)

target_link_libraries(sinsp-example
	sinsp
)

if (EMSCRIPTEN)
	target_compile_options(sinsp-example PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(sinsp-example PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(sinsp-example PRIVATE "-sEXPORTED_FUNCTIONS=['_main','_htons','_ntohs']")
endif()

if (APPLE AND NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
	# Needed when linking libcurl
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -framework Foundation -framework SystemConfiguration")
endif()
