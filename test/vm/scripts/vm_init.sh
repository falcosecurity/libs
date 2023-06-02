
#!/bin/bash

set -e

if [[ $# -ne 3 || "${EUID}" -eq 0 ]]; then
	echo "Usage: bash vm_init.sh BASE_DIR VM_PROVIDER VM_NAMES"
  echo "Run as non-root user"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";
VM_NAMES="${3}";

set -eou pipefail

echo "Init VMs";
pushd ${BASE_DIR}/vm_provider/${VM_PROVIDER};
vagrant destroy -f || true;
vagrant up;

for host in $(echo ${VM_NAMES})
do
    echo "${host}";
    SSH_BASE_COMMAND="ssh $(vagrant ssh-config ${host} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}') localhost";
    SCP_BASE_COMMAND="scp -r $(vagrant ssh-config ${host} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}')";
    ${SCP_BASE_COMMAND} ../../build/kernels localhost:/home/vagrant/kernels;
    ${SCP_BASE_COMMAND} ../../scripts/vagrant_provision.sh localhost:/home/vagrant/vagrant_provision.sh; 
    ${SSH_BASE_COMMAND} "sudo bash /home/vagrant/vagrant_provision.sh" || true;
done

popd