# note: since macOS is effectively non-existent, this library will go away
# as soon as we clean up the interface enough
add_library(scap_platform scap_procs.c)
add_dependencies(scap_platform zlib)
