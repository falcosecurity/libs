add_library(scap_platform scap_procs.c scap_fds.c scap_userlist.c scap_iflist.c ../posix_common/strerror.c)
target_link_libraries(scap_platform scap_error)
