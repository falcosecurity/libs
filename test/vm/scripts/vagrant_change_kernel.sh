#!/bin/bash

if [[ "${EUID}" -ne 0 ]]; then
  echo "Usage: sudo bash vagrant_change_kernel.sh"
  echo "Run as root user in VM"
  exit 1
fi

set -eou pipefail

NEXT_UNAME_R=""; # Leave empty, this is a template script
UNAME_R=$(uname -r);
printf "\n\n[STATUS] IN PROGRESS $UNAME_R -> $NEXT_UNAME_R\n\n";

# centos7
if [[ "${NEXT_UNAME_R}" == *"el7"* ]]; then
  sed -i "s/GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/" /etc/default/grub;
  yum install -y /home/vagrant/kernels/*.el7.elrepo.x86_64.rpm || true;
  ID=$(awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg | grep ${NEXT_UNAME_R} | cut -c1-2);
  grub2-set-default "${ID}";
  grub2-mkconfig -o /boot/grub2/grub.cfg;
  TEST=$( cat /boot/grub2/grub.cfg | grep ${NEXT_UNAME_R} | wc -l);
  if [[ ${TEST} -eq 0 ]]; then
    printf "\n\n[STATUS] FAILED ${NEXT_UNAME_R} not found in grub, destroy and rebuild VM\n\n"
    exit 1
  else
    printf "\n\n[STATUS] DONE ${NEXT_UNAME_R} grub configuration\n\n"
  fi
# ubuntu
elif [[ "${NEXT_UNAME_R}" == *"generic"* ]]; then
  apt-get install /home/vagrant/kernels/linux*amd64.deb -y || true;
  NAME="Advanced options for Ubuntu>Ubuntu, with Linux ${NEXT_UNAME_R}";
  sed -i "s/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"${NAME}\"/" /etc/default/grub;
  update-grub;
  TEST=$( cat /boot/grub/grub.cfg | grep ${NEXT_UNAME_R} | wc -l);
  if [[ ${TEST} -eq 0 ]]; then
    printf "\n\n[STATUS] FAILED ${NEXT_UNAME_R} not found in grub, destroy and rebuild VM\n\n"
    exit 1
  else
    printf "\n\n[STATUS] DONE ${NEXT_UNAME_R} grub configuration\n\n"
  fi
# amazonlinux2
elif [[ "${NEXT_UNAME_R}" == *".amzn2.x86_64"* ]]; then
  # Amazon Linux 2 doesn't let you install kernels easily ...
  if [[ "${NEXT_UNAME_R}" == *"5.4."* ]]; then
    amazon-linux-extras install kernel-5.4 -y
    yum install -y "/home/vagrant/kernels/kernel-${NEXT_UNAME_R}.rpm" || true;
  elif [[ "${NEXT_UNAME_R}" == *"4.14."* ]]; then
    yum install -y "/home/vagrant/kernels/kernel-${NEXT_UNAME_R}.rpm" || true;
  else
    printf "\n\n[STATUS] FAILED We only support kernels 4.14 and 5.4 for AmazonLinux2, ${NEXT_UNAME_R} is not supported.\n\n"
    exit 1
  fi
fi

reboot
