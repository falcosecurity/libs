#!/bin/bash

if [[ $# -ne 3 || "${EUID}" -eq 0 ]]; then
  echo "Usage: bash vagrant_loop.sh BASE_DIR VM_PROVIDER VM_NAME"
  echo "Run as non-root user on host"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";
VM_NAME="${3}";

# note: script needs to continue on failures by design
# script invokes vagrant_test_run.sh and vagrant_change_kernel.sh within VM while looping and rebooting into kernels

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
  printf "\n\n[STATUS] START unit tests over ssh remote commands for: ${kernel_uname_r}\n\n";
  for c in "${BASE_DIR}/build/driver"/*; do
    compiler_version=$(basename "$c");
    if [[ ( ! -f "${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}.o" && ${compiler_version} == *"clang"* ) || \
    ( ! -f "${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}.ko" && ${compiler_version} == *"gcc"* ) ]]; then
      continue
    fi

    cmd="sudo bash /home/vagrant/vagrant_test_run.sh ${compiler_version}";
    if ssh ${SSH_OPTIONS} localhost "${cmd}"; then 
      mkdir -p "${BASE_DIR}/build/driver_ok/${compiler_version}";
      if [[ "${compiler_version}" == *"clang"* ]]; then
        printf "\n\n[STATUS] SUCCESS ${compiler_version}/${kernel_uname_r}.o, proceed with next test\n\n";
        cp "${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}.o" "${BASE_DIR}/build/driver_ok/${compiler_version}/${kernel_uname_r}.o";
      elif [[ "${compiler_version}" == *"gcc"* ]]; then
        printf "\n\n[STATUS] SUCCESS ${compiler_version}/${kernel_uname_r}.ko, proceed with next test\n\n";
        cp "${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}.ko" "${BASE_DIR}/build/driver_ok/${compiler_version}/${kernel_uname_r}.ko";
        printf "\n\n[STATUS] Reboot to force unload kmod ...\n\n";
        ssh ${SSH_OPTIONS} localhost "sudo reboot"; 
        sleep 5;
      fi
    else
      printf "\n\n[STATUS] FAILED ${BASE_DIR}/build/driver/${compiler_version}/${kernel_uname_r}\n\n";
      if [[ "${compiler_version}" == *"gcc"* ]]; then
        if [[ ! ${VM_NAME} == *"amazonlinux2"* ]]; then
          # recover from possible kmod failure in a more robust manner
          printf "\n\n[STATUS] `vagrant reload` because of failed kmod test ...\n\n";
          vagrant reload "${VM_NAME}";
        else
          # amazonlinux hangs after failed kmod when using `vagrant reload`, only reboot as workaround
          printf "\n\n[STATUS] Sleeping and reboot because of failed kmod test ...\n\n";
          ssh ${SSH_OPTIONS} localhost "sudo reboot";
          sleep 15;
        fi
      fi
    fi
  done
}

export VAGRANT_CWD="${BASE_DIR}/vm_provider/${VM_PROVIDER}";
SSH_OPTIONS="$(vagrant ssh-config ${VM_NAME} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}')";
vagrant reload "${VM_NAME}";
KERNEL_DIR="${BASE_DIR}/build/headers_extracted";
mkdir -p "${BASE_DIR}/build/driver_ok";
KERNEL_FILTER="el7.elrepo";
if [[ ${VM_NAME} == *"ubuntu"* ]]; then
  KERNEL_FILTER="generic";
elif [[ ${VM_NAME} == *"amazonlinux2"* ]]; then
  KERNEL_FILTER=".amzn2.x86_64";
fi

# randomize order of loop
KERNELS=$( ls ${KERNEL_DIR} | grep -e ${KERNEL_FILTER} | grep -v "linux-modules" | shuf );
if [[ ${VM_NAME} == *"amazonlinux2"* ]]; then
  # workaround amazonlinux2, ensure in order for stability
  KERNELS=$( ls ${KERNEL_DIR} | grep -e ${KERNEL_FILTER} | grep -e 4.14 );
  KERNELS="${KERNELS} $( ls ${KERNEL_DIR} | grep -e ${KERNEL_FILTER} | grep -e 5.4 )";
fi

ssh ${SSH_OPTIONS} localhost "sudo rm -rf /home/vagrant/*";
scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/driver localhost:/home/vagrant/driver;
scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/kernels localhost:/home/vagrant/kernels;
scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/scap-open localhost:/home/vagrant/scap-open;
scp -r ${SSH_OPTIONS} ${BASE_DIR}/scripts/vagrant_test_run.sh localhost:/home/vagrant/vagrant_test_run.sh;

for k in ${KERNELS}; do
  next_uname_r=$(basename "${k}" | sed 's/^[^0-9]*//');
  printf "\n\n[STATUS] START ${next_uname_r}\n\n"
  sed "s/NEXT_UNAME_R=\"\";/NEXT_UNAME_R=${next_uname_r};/" "${BASE_DIR}/scripts/vagrant_change_kernel.sh" > "${BASE_DIR}/build/vagrant_change_kernel.sh";
  scp -r ${SSH_OPTIONS} ${BASE_DIR}/build/vagrant_change_kernel.sh localhost:/home/vagrant/vagrant_change_kernel.sh;
  ssh ${SSH_OPTIONS} localhost "sudo bash /home/vagrant/vagrant_change_kernel.sh";
  vagrant reload "${VM_NAME}";
  sleep 2;
  new_kernel=$(ssh ${SSH_OPTIONS} localhost "uname -r");
  new_kernel=$(echo "${new_kernel}" | sed $'s/[^[:print:]\t]//g');
  verify_kernel_change_success "${next_uname_r}" "${new_kernel}";
  unit_test ${new_kernel};
  printf "\n\n[STATUS] DONE ${new_kernel}\n\n"
done
