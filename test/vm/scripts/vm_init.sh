
#!/bin/bash

set -e

if [[ $# -ne 3 || "${EUID}" -eq 0 ]]; then
  echo "Usage: bash vm_init.sh BASE_DIR VM_PROVIDER VM_NAMES"
  echo "Run as non-root user on host"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";
VM_NAMES="${3}";

set -eou pipefail

echo "Init VMs";

export VAGRANT_CWD="${BASE_DIR}/vm_provider/${VM_PROVIDER}"; 
vagrant box update || true;
vagrant destroy -f || true;
vagrant up;

for host in $(echo ${VM_NAMES})
do
    echo "${host}";
    SSH_OPTIONS="$(vagrant ssh-config ${host} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}')";
    scp -r ${SSH_OPTIONS} "${BASE_DIR}/build/kernels" localhost:/home/vagrant/kernels;
    scp -r ${SSH_OPTIONS} "${BASE_DIR}/scripts/vagrant_provision.sh" localhost:/home/vagrant/vagrant_provision.sh; 
    ssh ${SSH_OPTIONS} localhost "sudo bash /home/vagrant/vagrant_provision.sh" || true;
done
