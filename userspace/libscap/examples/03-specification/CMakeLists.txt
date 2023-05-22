include_directories("../../../common")
include_directories("../..")

add_executable(scap-specification
	main.cpp)

target_link_libraries(scap-specification
	scap)
