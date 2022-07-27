# TODO: find a better way to determine if we run ebpf tests or not
if(NOT BUILD_BPF)
	message(WARNING e2e tests can only be run with the eBPF probe)
	return()
endif()

add_custom_target(e2e-containers
	COMMAND docker build
		--tag sinsp-example:latest
		-f ${CMAKE_CURRENT_SOURCE_DIR}/containers/sinsp.Dockerfile
		${CMAKE_BINARY_DIR}
	COMMAND docker build
		--tag falco-e2e-tester:latest
		-f ${CMAKE_CURRENT_SOURCE_DIR}/containers/tests.Dockerfile
		${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS sinsp-example driver bpf
)

add_custom_target(kmod-tests
	COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/report/kmod
	# Run e2e tests with the kernel module
	COMMAND docker run --rm
		--privileged
		--name falco-e2e-tester
		-e KERNEL_MODULE=/driver/scap.ko
		-v /var/run/docker.sock:/var/run/docker.sock
		-v ${CMAKE_CURRENT_BINARY_DIR}/report/kmod:/report
		falco-e2e-tester:latest
	DEPENDS e2e-containers
)

add_custom_target(ebpf-tests
	COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/report/ebpf
	# Run e2e tests with the eBPF probe
	COMMAND docker run --rm
		--privileged
		--name falco-e2e-tester
		-e BPF_PROBE=/driver/probe.o
		-v /var/run/docker.sock:/var/run/docker.sock
		-v ${CMAKE_CURRENT_BINARY_DIR}/report/ebpf:/report
		falco-e2e-tester:latest
	# Run eBPF tests after kmod
	DEPENDS e2e-containers kmod-tests
)

add_custom_target(e2e-tests
	DEPENDS ebpf-tests
)
