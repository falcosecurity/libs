set(UBUNTU_CONTAINER1 "vm1:ubuntu2004")
set(UBUNTU_CONTAINER2 "vm2:ubuntu2204")
set(UBUNTU_CONTAINER3 "vm3:ubuntu2310")
set(VM_PROVIDER "virtualbox")
set(VAGRANT_VM_NAMES "ubuntu centos7")


add_custom_target(vm-container
	COMMAND docker pull falcosecurity/falco-builder:latest;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu2004 -t ${UBUNTU_CONTAINER1} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu2204 -t ${UBUNTU_CONTAINER2} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/docker/Dockerfile.ubuntu2310 -t ${UBUNTU_CONTAINER3} .;
)

add_custom_target(vm-kernel
	COMMAND mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/build;
	COMMAND time docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/vm:z ${UBUNTU_CONTAINER2} '/bin/bash /vm/scripts/kernel_download.sh /vm/build /vm/kernels.txt';
	COMMAND time docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/vm:z ${UBUNTU_CONTAINER2} '/bin/bash /vm/scripts/kernel_extract.sh /vm/build/headers /vm/build/headers_extracted';
	DEPENDS vm-container
)

# Prepares containers, kernel packages and VMs for vm-tests - typically run once
add_custom_target(vm-init
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_init.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ${VAGRANT_VM_NAMES};
	DEPENDS vm-kernel
)

# Main test to build scap-open and each driver for array of compiler versions
add_custom_target(vm-compile
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_compile.sh ${CMAKE_CURRENT_SOURCE_DIR};
)

# Loop over centos7 kernels and test each driver for each compiler version - can run multiple times for dev/test to increase accuracy and resiliency
add_custom_target(vm-centos7
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} centos7';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

# Loop over ubuntu kernels and test each driver for each compiler version - can run multiple times for dev/test to increase accuracy and resiliency - ubuntu is more flaky, may need to re-kick
add_custom_target(vm-ubuntu
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER} ubuntu';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

# Option to re-create result output
add_custom_target(vm-result
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

set(VM_CONTAINERS
	${UBUNTU_CONTAINER1} 
	${UBUNTU_CONTAINER2} 
	${UBUNTU_CONTAINER3} 
	falcosecurity/falco-builder:latest
)

add_custom_target(vm-cleanup
	COMMAND docker rm -f ${VM_CONTAINERS};
	COMMAND docker image rm -f ${VM_CONTAINERS};
	COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_cleanup.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER};
)

