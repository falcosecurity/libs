
#!/bin/bash

set -e

if [[ $# -ne 2 ]]; then
	echo "Usage: all_vm_init.sh BASE_DIR VM_PROVIDER"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";

echo "Destroy VMs";
pushd ${BASE_DIR}/vm_provider/${VM_PROVIDER};
vagrant destroy -f || true;

echo "Delete driver_sanity/kernel_compat/build dir"
rm -rf ${BASE_DIR}/build;
popd