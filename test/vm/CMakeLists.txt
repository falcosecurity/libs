set(UBUNTU_CONTAINER1 "vm-ubuntu2004:latest")
set(UBUNTU_CONTAINER2 "vm-ubuntu2204:latest")
set(UBUNTU_CONTAINER3 "vm-ubuntu2310:latest")
set(DEBIANBUSTER_CONTAINER "vm-debianbuster:latest")
set(VM_PROVIDER_VBOX "virtualbox")
set(VM_NAMES_VBOX_VAGRANT_CENTOS7 "centos7")
set(VM_NAMES_VBOX_VAGRANT_UBUNTU "ubuntu")
set(VM_NAMES_VBOX_VAGRANT_AMAZONLINUX2 "amazonlinux2")
set(VM_NAMES_VBOX_VAGRANT "centos7 ubuntu amazonlinux2") # needs to be one string

set(VM_CONTAINERS
	${UBUNTU_CONTAINER1} 
	${UBUNTU_CONTAINER2} 
	${UBUNTU_CONTAINER3} 
	${DEBIANBUSTER_CONTAINER} 
	falcosecurity/falco-builder:latest
)

add_custom_target(vm-dependency-check
	COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/dependency_check.sh;
)

add_custom_target(vm-container
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/containers/ubuntu2004.Dockerfile -t ${UBUNTU_CONTAINER1} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/containers/ubuntu2204.Dockerfile  -t ${UBUNTU_CONTAINER2} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/containers/ubuntu2310.Dockerfile  -t ${UBUNTU_CONTAINER3} .;
	COMMAND time docker build -f ${CMAKE_CURRENT_SOURCE_DIR}/containers/debianbuster.Dockerfile  -t ${DEBIANBUSTER_CONTAINER} .;
	COMMAND docker pull falcosecurity/falco-builder:latest;
)

add_custom_target(vm-kernel
	COMMAND mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/build;
	COMMAND time docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/vm:z ${UBUNTU_CONTAINER2} '/bin/bash /vm/scripts/kernel_download.sh /vm/build /vm/kernels.jsonl';
	COMMAND time docker run -v ${CMAKE_CURRENT_SOURCE_DIR}:/vm:z ${UBUNTU_CONTAINER2} '/bin/bash /vm/scripts/kernel_extract.sh /vm/build/headers /vm/build/headers_extracted';
	DEPENDS vm-container
)

# Prepares containers, kernel packages and VMs for vm-tests - typically run once
add_custom_target(vm-init
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_init.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER_VBOX} ${VM_NAMES_VBOX_VAGRANT};
	DEPENDS vm-kernel
)

# Main test to build scap-open and each driver for array of compiler versions
add_custom_target(vm-compile
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_compile.sh ${CMAKE_CURRENT_SOURCE_DIR};
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

# Loop over centos7 kernels
add_custom_target(vm-centos7
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER_VBOX} ${VM_NAMES_VBOX_VAGRANT_CENTOS7}';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

# Loop over ubuntu kernels
add_custom_target(vm-ubuntu
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER_VBOX} ${VM_NAMES_VBOX_VAGRANT_UBUNTU}';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

# Loop over amazonlinux2 kernels, less stable, can have issues recovering from failed kmod tests
add_custom_target(vm-amazonlinux2
	COMMAND time bash -c 'bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vagrant_loop.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER_VBOX} ${VM_NAMES_VBOX_VAGRANT_AMAZONLINUX2}';
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

# Create result tables
add_custom_target(vm-result
	COMMAND time bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_result.sh ${CMAKE_CURRENT_SOURCE_DIR} ${UBUNTU_CONTAINER2};
)

add_custom_target(vm-cleanup
	COMMAND docker rm -f ${VM_CONTAINERS};
	COMMAND docker image rm -f ${VM_CONTAINERS};
	COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_cleanup.sh ${CMAKE_CURRENT_SOURCE_DIR} ${VM_PROVIDER_VBOX};
)
