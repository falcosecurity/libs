include_directories(${LIBSCAP_INCLUDE_DIRS})
add_library(scap_engine_noop noop.c)
add_dependencies(scap_engine_noop zlib)
