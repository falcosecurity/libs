include_directories("../../../common")
include_directories("../../")

add_executable(scap-open
	scap_open.c)

target_link_libraries(scap-open
	scap)
