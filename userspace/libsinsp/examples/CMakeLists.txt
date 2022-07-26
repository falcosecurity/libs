include_directories("../../../common")
include_directories("../../")

add_executable(sinsp-example
	util.cpp
	test.cpp
)

target_link_libraries(sinsp-example
	sinsp
)

if (APPLE AND NOT MINIMAL_BUILD)
	# Needed when linking libcurl
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -framework Foundation -framework SystemConfiguration")
endif()
