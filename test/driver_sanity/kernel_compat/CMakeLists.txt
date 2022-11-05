set(UBUNTU_CONTAINER1 "driver-sanity1:ubuntu20.04")
set(UBUNTU_CONTAINER2 "driver-sanity2:ubuntu22.04")
set(VM_PROVIDER "virtualbox")
set(VAGRANT_VM_NAMES "ubuntu centos7")


add_custom_target(driver-sanity-container
	COMMAND docker pull falcosecurity/falco-builder:latest;
	COMMAND docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu20.04 -t ${UBUNTU_CONTAINER1} .;
	COMMAND docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu22.04 -t ${UBUNTU_CONTAINER2} .;
)

add_custom_target(driver-sanity-kernel
	COMMAND mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/build;
	COMMAND docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/driver-sanity:z ${UBUNTU_CONTAINER2} '/bin/bash /driver-sanity/scripts/kernel_download.sh /driver-sanity/build /driver-sanity/kernels.txt';
	COMMAND docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/driver-sanity:z ${UBUNTU_CONTAINER2} '/bin/bash /driver-sanity/scripts/kernel_extract.sh /driver-sanity/build/headers /driver-sanity/build/headers_extracted';
	DEPENDS driver-sanity-container
)

# Prepares containers, kernel packages and VMs for driver-sanity-tests - typically run once
add_custom_target(driver-sanity-init
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_vm_init.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ${VAGRANT_VM_NAMES};
	DEPENDS driver-sanity-kernel
)

# Main test to build scap-open, all drivers and test launch in VMs - can run multiple times for dev/test - on purpose no dependency on driver-sanity-init
add_custom_target(driver-sanity-tests
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_driver_sanity_test_run.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ${VAGRANT_VM_NAMES} ${UBUNTU_CONTAINER2};
	COMMAND bash -c 'cp -f ${CMAKE_CURRENT_SOURCE_DIR}/build/driver_compat_matrix.png ${CMAKE_CURRENT_BINARY_DIR}/driver_compat_matrix.png';
)

set(DRIVER_SANITY_CONTAINERS
	${UBUNTU_CONTAINER1} 
	${UBUNTU_CONTAINER2} 
	falcosecurity/falco-builder:latest
)

add_custom_target(driver-sanity-cleanup
	COMMAND docker rm -f ${DRIVER_SANITY_CONTAINERS};
	COMMAND docker image rm -f ${DRIVER_SANITY_CONTAINERS};
	COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_cleanup.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER};
)

