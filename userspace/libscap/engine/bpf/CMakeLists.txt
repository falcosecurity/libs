include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_bpf scap_bpf.c attached_prog.c)
add_dependencies(scap_engine_bpf libelf scap_platform)
target_link_libraries(scap_engine_bpf scap_event_schema scap_platform scap_engine_util scap_error ${LIBELF_LIB})
target_include_directories(scap_engine_bpf PRIVATE ${LIBELF_INCLUDE})

set_scap_target_properties(scap_engine_bpf)
