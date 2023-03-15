set(UBUNTU_CONTAINER1 "driver-sanity1:ubuntu20.04")
set(UBUNTU_CONTAINER2 "driver-sanity2:ubuntu22.04")
set(UBUNTU_CONTAINER3 "driver-sanity3:ubuntu23.04")
set(VM_PROVIDER "virtualbox")
set(VAGRANT_VM_NAMES "ubuntu centos7")


add_custom_target(driver-sanity-container
	COMMAND docker pull falcosecurity/falco-builder:latest;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu20.04 -t ${UBUNTU_CONTAINER1} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu22.04 -t ${UBUNTU_CONTAINER2} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu23.04 -t ${UBUNTU_CONTAINER3} .;
)

add_custom_target(driver-sanity-kernel
	COMMAND mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/build;
	COMMAND time docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/driver-sanity:z ${UBUNTU_CONTAINER2} '/bin/bash /driver-sanity/scripts/kernel_download.sh /driver-sanity/build /driver-sanity/kernels.txt';
	COMMAND time docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/driver-sanity:z ${UBUNTU_CONTAINER2} '/bin/bash /driver-sanity/scripts/kernel_extract.sh /driver-sanity/build/headers /driver-sanity/build/headers_extracted';
	DEPENDS driver-sanity-container
)

# Prepares containers, kernel packages and VMs for driver-sanity-tests - typically run once
add_custom_target(driver-sanity-init
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_vm_init.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ${VAGRANT_VM_NAMES};
	DEPENDS driver-sanity-kernel
)

# Main test to build scap-open and each driver for array of compiler versions
add_custom_target(driver-sanity-compile
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_driver_sanity_test_compile.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ${VAGRANT_VM_NAMES} ${UBUNTU_CONTAINER2};
)

# Loop over centos7 kernels and test each driver for each compiler version - can run multiple times for dev/test to increase accuracy and resiliency
add_custom_target(driver-sanity-tests-centos7
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} centos7';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_driver_sanity_test_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
	COMMAND bash -c 'cp -f ${CMAKE_CURRENT_SOURCE_DIR}/build/driver_compat_matrix.png ${CMAKE_CURRENT_BINARY_DIR}/driver_compat_matrix.png';
)

# Loop over ubuntu kernels and test each driver for each compiler version - can run multiple times for dev/test to increase accuracy and resiliency - ubuntu is more flaky, may need to re-kick
add_custom_target(driver-sanity-tests-ubuntu
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ubuntu';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_driver_sanity_test_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
	COMMAND bash -c 'cp -f ${CMAKE_CURRENT_SOURCE_DIR}/build/driver_compat_matrix.png ${CMAKE_CURRENT_BINARY_DIR}/driver_compat_matrix.png';
)

# Option to re-create results output
add_custom_target(driver-sanity-results
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_driver_sanity_test_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
	COMMAND bash -c 'cp -f ${CMAKE_CURRENT_SOURCE_DIR}/build/driver_compat_matrix.png ${CMAKE_CURRENT_BINARY_DIR}/driver_compat_matrix.png';
)

set(DRIVER_SANITY_CONTAINERS
	${UBUNTU_CONTAINER1} 
	${UBUNTU_CONTAINER2} 
	${UBUNTU_CONTAINER3} 
	falcosecurity/falco-builder:latest
)

add_custom_target(driver-sanity-cleanup
	COMMAND docker rm -f ${DRIVER_SANITY_CONTAINERS};
	COMMAND docker image rm -f ${DRIVER_SANITY_CONTAINERS};
	COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/all_cleanup.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER};
)

