add_library(scap_platform scap_linux_platform.c scap_procs.c scap_fds.c scap_userlist.c scap_iflist.c scap_ppm_sc.c)
target_link_libraries(scap_platform scap_error scap_platform_util)
set_scap_target_properties(scap_platform)
