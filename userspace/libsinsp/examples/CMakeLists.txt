include_directories("../../../common")
include_directories("../../")

add_executable(sinsp-example
	util.cpp
	test.cpp
)

target_link_libraries(sinsp-example
	sinsp
)

target_link_options(sinsp-example PRIVATE -sENVIRONMENT=web)
target_link_options(sinsp-example PRIVATE -sEXPORT_NAME='createModule')
target_link_options(sinsp-example PRIVATE -lembind)
target_link_options(sinsp-example PRIVATE --pre-jslocateFile.js)
target_link_options(sinsp-example PRIVATE -sUSE_ES6_IMPORT_META=0)
target_link_options(sinsp-example PRIVATE -sMODULARIZE=1)
target_link_options(sinsp-example PRIVATE "-O3") 


if (APPLE AND NOT MINIMAL_BUILD AND NOT CMAKE_SYSTEM_NAME MATCHES "Emscripten")
	# Needed when linking libcurl
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -framework Foundation -framework SystemConfiguration")
endif()
