# This function must be used to retrieve a static library. This could be useful
# if we want to obtain a unique executable linked with only static libraries.
# - `LIB_NAME` is the full name of the library (for example `elf`)
# - `OUT` is the full path of the library that should be passed to `target_link_libraries`

function(find_static_library LIB_NAME OUT)

  if(UNIX)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
  endif()

  find_library(FOUND_${LIB_NAME}_STATIC ${LIB_NAME})

  if(FOUND_${LIB_NAME}_STATIC)
    get_filename_component(ABS_FILE ${FOUND_${LIB_NAME}_STATIC} ABSOLUTE)
  else()
    message(SEND_ERROR "Unable to find library ${LIB_NAME}")
  endif()

  set(${OUT}
      ${ABS_FILE}
      PARENT_SCOPE)

endfunction()
