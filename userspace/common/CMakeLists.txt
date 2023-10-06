add_library(falcosecurity_log INTERFACE)
target_include_directories(falcosecurity_log
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/falcosecurity>
        $<INSTALL_INTERFACE:common/falcosecurity>)
