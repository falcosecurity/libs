include_directories("../../../common")
include_directories("../../")

option(WITH_CHISEL on)

add_executable(sinsp-example
	util.cpp
	test.cpp
)

target_link_libraries(sinsp-example
	sinsp
)
