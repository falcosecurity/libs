#!/bin/bash

if [[ $# -ne 3 ]]; then
	echo "Usage: bash vagrant_loop.sh BASE_DIR VM_PROVIDER VM_NAME"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";
VM_NAME="${3}";

pushd ${BASE_DIR}/vm_provider/${VM_PROVIDER};

SSH_BASE_COMMAND="ssh $(vagrant ssh-config ${VM_NAME} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}') localhost";
SCP_BASE_COMMAND="scp -r $(vagrant ssh-config ${VM_NAME} | sed '/^[[:space:]]*$/d' |  awk 'NR>1 {print " -o "$1"="$2}')";
KERNEL_DIR="../../build/headers_extracted";
mkdir -p "../../build/driver-ok";
KERNEL_FILTER="el7";
if [[ ${VM_NAME} == *"ubuntu"* ]]; then
    KERNEL_FILTER="generic";
fi

KERNELS=$( ls ${KERNEL_DIR} | grep -e ${KERNEL_FILTER} | grep -v "linux-modules" );
${SCP_BASE_COMMAND} ../../build/driver localhost:/home/vagrant/driver;
${SCP_BASE_COMMAND} ../../build/kernels localhost:/home/vagrant/kernels;
${SCP_BASE_COMMAND} ../../build/scap-open localhost:/home/vagrant/scap-open;
${SCP_BASE_COMMAND} ../../scripts/vagrant_scap_open_test.sh localhost:/home/vagrant/vagrant_scap_open_test.sh;

function verify_kernel_change_success ()
{
  if [[ ${1} == ${2}* ]]; then
    printf "\n\nKernel updated correctly to ${1}, proceed with scap-open unit tests\n\n";
  else
    printf "\n\nNew kernel ${1} not updated correctly from previous kernel ${2}\n\n"; 
    exit 1;
  fi;
}

function unit_test()
{
  kernel_uname_r="${1}";
  versions="../../build/driver/*";
  for compiler_version in $versions
  do
    if [[ ! -f "../../build/driver/${compiler_version}/${kernel_uname_r}.o" && ${compiler_version} == *"clang"* ]]; then
      continue
    elif [[ ! -f "../../build/driver/${compiler_version}/${kernel_uname_r}.ko" && ${compiler_version} == *"gcc"* ]]; then
      continue
    fi
    compiler_version=$(basename $compiler_version);
    echo ${compiler_version}
    cmd="sudo bash /home/vagrant/vagrant_scap_open_test.sh ${compiler_version}";
    if ${SSH_BASE_COMMAND} "${cmd}"; then 
      echo "OK ${compiler_version}";
      mkdir -p "../../build/driver-ok/${compiler_version}";
      if [[ ${compiler_version} == *"clang"* ]]; then
        cp "../../build/driver/${compiler_version}/${kernel_uname_r}.o" "../../build/driver-ok/${compiler_version}/${kernel_uname_r}.o";
      elif [[ ${compiler_version} == *"gcc"* ]]; then
        cp "../../build/driver/${compiler_version}/${kernel_uname_r}.ko" "../../build/driver-ok/${compiler_version}/${kernel_uname_r}.ko";
        ${SSH_BASE_COMMAND} "sudo reboot"; sleep 10;
      fi
    else
      echo "FAILED unit test for ../../build/driver/${compiler_version}/${kernel_uname_r}";
      if [[ ${compiler_version} == *"gcc"* ]]; then
        ${SSH_BASE_COMMAND} "sudo reboot"; sleep 15;
      fi
    fi
  done

}

for k in ${KERNELS}
do
  next_uname_r=$(basename "${k}" | sed 's/^[^0-9]*//');
  printf "\n\n\n\nNext up kernel ${next_uname_r}\n\n\n\n"
  sed "s/NEXT_UNAME_R=\"\";/NEXT_UNAME_R=${next_uname_r};/" "../../scripts/vagrant_change_kernel.sh" > "../../build/vagrant_change_kernel.sh";

  ${SCP_BASE_COMMAND} ../../build/vagrant_change_kernel.sh localhost:/home/vagrant/vagrant_change_kernel.sh;
  ${SSH_BASE_COMMAND} "sudo bash /home/vagrant/vagrant_change_kernel.sh";

  printf "\n\n\n\nSleeping ...\n\n\n\n";
  sleep 40;
  new_kernel=$(${SSH_BASE_COMMAND} "uname -r");
  new_kernel=$(echo ${new_kernel} | sed $'s/[^[:print:]\t]//g');
  verify_kernel_change_success ${next_uname_r} ${new_kernel};
  unit_test ${new_kernel};
done

popd
