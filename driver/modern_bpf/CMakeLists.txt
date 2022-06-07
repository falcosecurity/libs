option(MODERN_BPF_DEBUG_MODE "Enable BPF debug prints" OFF)

if(MODERN_BPF_DEBUG_MODE)
  set(DEBUG "MODERN_BPF_DEBUG")
else()
  set(DEBUG "")
endif()

#### TODO: we could add checks on the minimum required clang version.
find_program(CLANG_EXE NAMES clang DOC "Path to clang executable")

## Get bpftool executable
find_program(BPFTOOL_EXE NAMES bpftool DOC "Path to bpftool executable")

## Get clang bpf system includes
execute_process(
  COMMAND bash -c "${CLANG_EXE} -v -E - < /dev/null 2>&1 |
          sed -n '/<...> search starts here:/,/End of search list./{ s| \\(/.*\\)|-idirafter \\1|p }'"
  OUTPUT_VARIABLE CLANG_SYSTEM_INCLUDES_output
  ERROR_VARIABLE CLANG_SYSTEM_INCLUDES_error
  RESULT_VARIABLE CLANG_SYSTEM_INCLUDES_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${CLANG_SYSTEM_INCLUDES_result} EQUAL 0)
  string(REPLACE "\n" " " CLANG_SYSTEM_INCLUDES ${CLANG_SYSTEM_INCLUDES_output})
  message(STATUS "BPF system include flags: ${CLANG_SYSTEM_INCLUDES}")
else()
  message(FATAL_ERROR "Failed to determine BPF system includes: ${CLANG_SYSTEM_INCLUDES_error}")
endif()

## Get vmlinux directory
set(VMLINUX_FILE ${CMAKE_CURRENT_SOURCE_DIR}/definitions/vmlinux.h)
get_filename_component(VMLINUX_DIR ${VMLINUX_FILE} DIRECTORY)

## Get target arch (right now we explicitly support only `x86` and `arm64`)
execute_process(COMMAND uname -m
  COMMAND sed "s/x86_64/x86/"
  COMMAND sed "s/aarch64/arm64/"
  COMMAND sed "s/ppc64le/powerpc/"
  COMMAND sed "s/mips.*/mips/"
  OUTPUT_VARIABLE ARCH_output
  ERROR_VARIABLE ARCH_error
  RESULT_VARIABLE ARCH_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${ARCH_result} EQUAL 0)
  set(ARCH ${ARCH_output})
  message(STATUS "Target arch: ${ARCH}")
else()
  message(FATAL_ERROR "Failed to determine target architecture: ${ARCH_error}")
endif()

# Get modern probe include.
set(MODERN_PROBE_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR})

# Get PPM include.
set(PPM_INCLUDE ${CMAKE_SOURCE_DIR}/driver/)

## Set CLANG FLAGS
set(CLANG_FLAGS "")
list(APPEND CLANG_FLAGS
    -g -O2
    -target bpf
    -D__${DEBUG}__
    -D__TARGET_ARCH_${ARCH} # Match libbpf usage in `/libbpf/src/bpf_tracing.h`
    -D__USE_VMLINUX__ # Used to compile without kernel headers.
    -I${LIBBPF_INCLUDE}
    -I${VMLINUX_DIR}
    -I${MODERN_PROBE_INCLUDE}
    -I${PPM_INCLUDE}
    -isystem
)

## Search all bpf includes files. (we can use bpf.h files)
file(GLOB_RECURSE BPF_H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

## Search all bpf.c files
file(GLOB_RECURSE BPF_C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.bpf.c)

## Generate an bpf.o file for every bpf.c
foreach(BPF_C_FILE ${BPF_C_FILES})
    get_filename_component(file_stem ${BPF_C_FILE} NAME_WE)
    set(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${file_stem}.bpf.o)

    add_custom_command(
        OUTPUT ${BPF_O_FILE}
        COMMAND ${CLANG_EXE} ${CLANG_FLAGS} ${CLANG_SYSTEM_INCLUDES} -c ${BPF_C_FILE} -o ${BPF_O_FILE}
        VERBATIM
        DEPENDS libbpf
        DEPENDS ${BPF_C_FILE} ${BPF_H_FILES} 
        COMMENT "[clang] Building BPF object: ${BPF_O_FILE}"
    )

    list(APPEND BPF_OBJECT_FILES ${BPF_O_FILE})
endforeach()

## Generate a unique bpf.o file
set(UNIQUE_BPF_O_FILE_NAME bpf_probe)
set(UNIQUE_BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${UNIQUE_BPF_O_FILE_NAME}.o)
add_custom_command(
  OUTPUT ${UNIQUE_BPF_O_FILE}
  COMMAND ${BPFTOOL_EXE} gen object ${UNIQUE_BPF_O_FILE} ${BPF_OBJECT_FILES}
  VERBATIM
  DEPENDS ${BPF_OBJECT_FILES}
  COMMENT "[bpftool]  Building BPF unique object file: ${UNIQUE_BPF_O_FILE}"
) 

## Generate the skeleton file
set(BPF_SKEL_FILE ${SKEL_DIR}/${UNIQUE_BPF_O_FILE_NAME}.skel.h)
add_custom_command(
    OUTPUT ${BPF_SKEL_FILE}
    COMMAND bash -c "${BPFTOOL_EXE} gen skeleton ${UNIQUE_BPF_O_FILE} > ${BPF_SKEL_FILE}"
    VERBATIM
    DEPENDS ${UNIQUE_BPF_O_FILE}
    COMMENT "[bpftool]  Building BPF skeleton: ${BPF_SKEL_FILE}"
)

## Add the skeleton as a custom target
set(BPF_SKEL_TARGET ProbeSkeleton)
add_custom_target(${BPF_SKEL_TARGET} ALL DEPENDS ${BPF_SKEL_FILE})

