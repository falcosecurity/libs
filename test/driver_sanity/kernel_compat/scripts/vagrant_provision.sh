#!/bin/bash
set -e

if [[ "${EUID}" -ne 0 ]]; then
  echo "Usage: sudo bash vagrant_provision.sh"
  echo "Run as root user in VM"
  exit 1
fi

UNAME_R=$(uname -r);
set -eou pipefail

echo "Running vagrant_provision.sh in VM";

if [[ "${UNAME_R}" == *"el7"* ]]; then
    yum install -y /home/vagrant/kernels/*.el7.elrepo.x86_64.rpm;
    sed -i "s/GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/" /etc/default/grub;
    ID=$(awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg | grep -v "3.10" | grep -v rescue | tail -1 | cut -c1-2);
    grub2-set-default "${ID}";
    grub2-mkconfig -o /boot/grub2/grub.cfg;
    cat /boot/grub2/grub.cfg;
fi

if [[ "${UNAME_R}" == *"generic"* ]]; then
    apt-get install /home/vagrant/kernels/linux*amd64.deb -y;
fi

reboot
