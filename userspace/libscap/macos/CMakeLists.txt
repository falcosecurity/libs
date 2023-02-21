# note: since macOS is effectively non-existent, this library will go away
# as soon as we clean up the interface enough
add_library(scap_platform scap_procs.c scap_ppm_sc.c)
set_scap_target_properties(scap_platform)
