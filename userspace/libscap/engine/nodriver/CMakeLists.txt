include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_nodriver OBJECT nodriver.c)
