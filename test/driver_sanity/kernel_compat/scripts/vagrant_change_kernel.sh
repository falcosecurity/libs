#!/bin/bash

if [[ "${EUID}" -ne 0 ]]; then
  echo "Usage: sudo bash vagrant_change_kernel.sh"
  echo "Run as root user in VM"
  exit 1
fi

set -eou pipefail

NEXT_UNAME_R=""; # Leave empty, this is a template script
UNAME_R=$(uname -r);
printf "\n\n\n\nCurrent kernel $UNAME_R -> $NEXT_UNAME_R\n\n\n\n";

if [[ "${NEXT_UNAME_R}" == *"el7"* ]]; then
  sed -i "s/GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/" /etc/default/grub;
  yum install -y /home/vagrant/kernels/*.el7.elrepo.x86_64.rpm || true;
  ID=$(awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg | grep ${NEXT_UNAME_R} | cut -c1-2);
  echo ${ID};
  grub2-set-default "${ID}";
  grub2-mkconfig -o /boot/grub2/grub.cfg;
  TEST=$( cat /boot/grub2/grub.cfg | grep ${NEXT_UNAME_R} | wc -l);
  if [[ ${TEST} -eq 0 ]]; then
    echo "Next kernel ${NEXT_UNAME_R} not found in grub, consider destroying and rebuilding the VM"
    exit 1
  else
    printf "\n\nSuccesfully configured next kernel ${NEXT_UNAME_R} in grub\n\n"
  fi
elif [[ "${NEXT_UNAME_R}" == *"generic"* ]]; then
  apt-get install /home/vagrant/kernels/linux*amd64.deb -y || true;
  NAME="Advanced options for Ubuntu>Ubuntu, with Linux ${NEXT_UNAME_R}";
  echo ${NAME};
  sed -i "s/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"${NAME}\"/" /etc/default/grub;
  update-grub;
  TEST=$( cat /boot/grub/grub.cfg | grep ${NEXT_UNAME_R} | wc -l);
  if [[ ${TEST} -eq 0 ]]; then
    echo "Next kernel ${NEXT_UNAME_R} not found in grub, consider destroying and rebuilding the VM"
    exit 1
  else
    printf "\n\nSuccesfully configured next kernel ${NEXT_UNAME_R} in grub\n\n"
  fi
fi

reboot
