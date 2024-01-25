option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS)
	# Add engine only used for testing
	set(HAS_ENGINE_TEST_INPUT On)
endif()

set(HAS_ENGINE_NODRIVER On)
set(HAS_ENGINE_SAVEFILE On)
set(HAS_ENGINE_SOURCE_PLUGIN On)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	option(ENABLE_ENGINE_KMOD "Enable kernel module engine" ON)
	option(ENABLE_ENGINE_BPF "Enable bpf engine" ON)

	set(HAS_ENGINE_KMOD ${ENABLE_ENGINE_KMOD})
	set(HAS_ENGINE_BPF ${ENABLE_ENGINE_BPF})

	option(BUILD_LIBSCAP_MODERN_BPF "Enable modern bpf probe" OFF)
	if(BUILD_LIBSCAP_MODERN_BPF)
		set(HAS_ENGINE_MODERN_BPF On)
	endif()
endif()

# gVisor is currently only supported on Linux x86_64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" AND CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT MINIMAL_BUILD)
	option(BUILD_LIBSCAP_GVISOR "Build gVisor support" ON)
	if (BUILD_LIBSCAP_GVISOR)
		set(HAS_ENGINE_GVISOR On)
	endif()
endif()
