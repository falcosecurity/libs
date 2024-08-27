# TODO: find a better way to determine if we run ebpf tests or not
if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
	return()
endif()

if(NOT BUILD_BPF)
	message(WARNING "e2e tests can only be run with the eBPF probe")
	return()
endif()

set(E2E_CONTEXT ${CMAKE_CURRENT_BINARY_DIR}/ctx)

# When running in CI, dump the reports in /tmp/
if(DEFINED ENV{CI})
    set(E2E_REPORT /tmp/)
else()
    set(E2E_REPORT ${CMAKE_CURRENT_BINARY_DIR})
endif()

add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})

add_custom_target(e2e-install-deps
	COMMAND pip3 install -r ${CMAKE_CURRENT_SOURCE_DIR}/tests/requirements.txt
	COMMAND pip3 install ${CMAKE_CURRENT_SOURCE_DIR}/tests/commons/
)

add_custom_target(e2e-context
	COMMAND mkdir -p ${E2E_CONTEXT}
	COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/libsinsp/examples/sinsp-example ${E2E_CONTEXT}
	COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/driver/scap.ko ${E2E_CONTEXT}
	COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/driver/bpf/probe.o ${E2E_CONTEXT}
	DEPENDS sinsp-example driver bpf
)

add_custom_target(e2e-containers
	COMMAND docker build
		--tag sinsp-example:latest
		-f ${CMAKE_CURRENT_SOURCE_DIR}/containers/sinsp.Dockerfile
		${E2E_CONTEXT}
	COMMAND docker build
		--tag sinsp-e2e-tester:latest
		-f ${CMAKE_CURRENT_SOURCE_DIR}/containers/tests.Dockerfile
		${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS e2e-context
)

add_custom_target(e2e-tests-container
	COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/report
	# Run e2e tests with the kernel module
	COMMAND docker run --rm
		--name sinsp-e2e-tester
		-e KERNEL_MODULE=/driver/scap.ko
		-e BPF_PROBE=/driver/probe.o
		-v /var/run/docker.sock:/var/run/docker.sock
		-v ${E2E_REPORT}/report:/report
		sinsp-e2e-tester:latest
	DEPENDS e2e-containers
)

add_custom_target(e2e-tests
	COMMAND mkdir -p ${E2E_REPORT}/report
	# Run e2e tests with the kernel module
	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_tests.sh
	DEPENDS sinsp-example driver bpf
)

# This is a list of containers run by the e2e tests, if you add a different one
# please add it to the list
set(E2E_CONTAINERS
	sinsp
	nginx
	sinsp-e2e-tester
	curl
	generator
	http-hello
)

 add_custom_target(e2e-cleanup
	 COMMAND docker rm -f ${E2E_CONTAINERS}
)
