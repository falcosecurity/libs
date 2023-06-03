#!/bin/bash

if [[ $# -ne 3 || "${EUID}" -eq 0 ]]; then
  echo "Usage: bash vagrant_loop.sh BASE_DIR VM_PROVIDER VM_NAME"
  echo "Run as non-root user outside of VM"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";
VM_NAME="${3}";

# note: script needs to continue on failures by design
# script invokes vagrant_test_run.sh and vagrant_change_kernel.sh within VM while looping and rebooting into kernels
export VAGRANT_CWD="${BASE_DIR}/vm_provider/${VM_PROVIDER}";
SSH_OPTIONS="$(vagrant ssh-config ${VM_NAME} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}')";
KERNEL_DIR="${BASE_DIR}/build/headers_extracted";
mkdir -p "${BASE_DIR}/build/driver_ok";
KERNEL_FILTER="el7";
if [[ ${VM_NAME} == *"ubuntu"* ]]; then
    KERNEL_FILTER="generic";
fi

# randomize order of loop, to help with flakiness when re-running tests
KERNELS=$( ls ${KERNEL_DIR} | grep -e ${KERNEL_FILTER} | grep -v "linux-modules" | shuf );
scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/driver localhost:/home/vagrant/driver;
scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/kernels localhost:/home/vagrant/kernels;
scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/scap-open localhost:/home/vagrant/scap-open;
scp -r ${SSH_OPTIONS} ${BASE_DIR}/scripts/vagrant_test_run.sh localhost:/home/vagrant/vagrant_test_run.sh;

function verify_kernel_change_success()
{
  if [[ ! -z "${1}" && ! -z "${2}" && ${1} == ${2}* ]]; then
    printf "\n\n[STATUS] SUCCESS ${1} kernel change, proceed with unit tests\n\n";
  else
    printf "\n\n[STATUS] FAILED ${2} -> ${1} kernel change\n\n";
    exit 1;
  fi;
}

function unit_test()
{
  kernel_uname_r="${1}";
  for compiler_version in "${BASE_DIR}/build/driver"/*; do
    if [[ ( ! -f "${compiler_version}/${kernel_uname_r}.o" && ${compiler_version} == *"clang"* ) || \
    ( ! -f "${compiler_version}/${kernel_uname_r}.ko" && ${compiler_version} == *"gcc"* ) ]]; then
      continue
    fi
    compiler_version=$(basename "$compiler_version");
    cmd="sudo bash /home/vagrant/vagrant_test_run.sh ${compiler_version}";
    if ssh ${SSH_OPTIONS} localhost "${cmd}"; then 
      mkdir -p "${BASE_DIR}/build/driver_ok/${compiler_version}";
      if [[ "${compiler_version}" == *"clang"* ]]; then
        printf "\n\n[STATUS] SUCCESS ${compiler_version}/${kernel_uname_r}.o, proceed with next test\n\n";
        cp "${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}.o" "${BASE_DIR}/build/driver_ok/${compiler_version}/${kernel_uname_r}.o";
      elif [[ "${compiler_version}" == *"gcc"* ]]; then
        printf "\n\n[STATUS] SUCCESS ${compiler_version}/${kernel_uname_r}.ko, proceed with next test\n\n";
        cp "${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}.ko" "${BASE_DIR}/build/driver_ok/${compiler_version}/${kernel_uname_r}.ko";
        ssh ${SSH_OPTIONS} localhost "sudo reboot"; 
        sleep 5;
      fi
    else
      printf "\n\n[STATUS] FAILED ${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}\n\n";
      if [[ "${compiler_version}" == *"gcc"* ]]; then
        vagrant reload "${VM_NAME}" # needed to recover from possible kmod failure
      fi
    fi
  done

}

for k in ${KERNELS}; do
  vagrant reload "${VM_NAME}" # more robust than reboot to ensure kernel change works, kmod tests interfere heavily :/
  next_uname_r=$(basename "${k}" | sed 's/^[^0-9]*//');
  printf "\n\n[STATUS] START ${next_uname_r}\n\n"
  sed "s/NEXT_UNAME_R=\"\";/NEXT_UNAME_R=${next_uname_r};/" "${BASE_DIR}/scripts/vagrant_change_kernel.sh" > "${BASE_DIR}/build/vagrant_change_kernel.sh";

  scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/vagrant_change_kernel.sh localhost:/home/vagrant/vagrant_change_kernel.sh;
  ssh ${SSH_OPTIONS} localhost "sudo bash /home/vagrant/vagrant_change_kernel.sh";

  vagrant reload "${VM_NAME}" # second time for even more robustness as kmod tests interfere heavily :/
  new_kernel=$(ssh ${SSH_OPTIONS} localhost "uname -r");
  new_kernel=$(echo "${new_kernel}" | sed $'s/[^[:print:]\t]//g');
  verify_kernel_change_success "${next_uname_r}" "${new_kernel}";
  unit_test ${new_kernel};
  printf "\n\n[STATUS] DONE ${new_kernel}\n\n"
done
