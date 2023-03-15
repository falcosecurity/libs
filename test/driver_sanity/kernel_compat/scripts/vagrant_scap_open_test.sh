#!/bin/bash

if [[ $# -ne 1 || "${EUID}" -ne 0 ]]; then
  echo "Usage: sudo bash vagrant_scap_open_test.sh COMPILER"
  echo "Run as root user in VM"
  exit 1
fi

COMPILER="${1}";
set -eou pipefail

echo "Test run for compiler/kernel ${COMPILER}/$(uname -r)"

rm -f /tmp/o;
# background scap-open
if [[ ${COMPILER} == *"clang"* ]]; then
  /home/vagrant/scap-open --bpf "/home/vagrant/driver/${COMPILER}/$(uname -r).o" > /tmp/o &
elif [[ ${COMPILER} == *"gcc"* ]]; then
  cp -f "/home/vagrant/driver/${COMPILER}/$(uname -r).ko" /home/vagrant/scap.ko;
  insmod /home/vagrant/scap.ko; lsmod | grep scap;
  /home/vagrant/scap-open --kmod > /tmp/o &
  # we don't remove the kernel module as we reboot to recover from possible buggy kmod attempts
else
  exit 0
fi

sleep 3;
# SIGINT to force STDOUT be captured in file for verification
pkill -SIGINT scap-open;
cat /tmp/o;
sleep 1;

TEST=$(cat /tmp/o | grep 'captured' | sed "s/[^0-9]//g");

if [[ ${TEST} -ge "10" ]]; then
    exit 0
else
    exit 1
fi
