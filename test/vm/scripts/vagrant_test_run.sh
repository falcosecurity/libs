#!/bin/bash

if [[ $# -ne 1 || "${EUID}" -ne 0 ]]; then
  echo "Usage: sudo bash vagrant_test_run.sh COMPILER"
  echo "Run as root user in VM"
  exit 1
fi

COMPILER="${1}";
set -eou pipefail

printf "\n\n[STATUS] START TEST RUN ${COMPILER}/$(uname -r)\n\n"

OUTPUT_FILE="$(mktemp)";

# background scap-open
if [[ ${COMPILER} == *"clang"* ]]; then
  /home/vagrant/scap-open --bpf "/home/vagrant/driver/${COMPILER}/$(uname -r).o" | tee ${OUTPUT_FILE} &
elif [[ ${COMPILER} == *"gcc"* ]]; then
  cp -f "/home/vagrant/driver/${COMPILER}/$(uname -r).ko" /home/vagrant/scap.ko;
  insmod /home/vagrant/scap.ko; lsmod | grep scap;
  /home/vagrant/scap-open --kmod | tee ${OUTPUT_FILE} &
  # we don't remove the kernel module as we reboot to recover from possible buggy kmod attempts
else
  exit 0
fi

sleep 5;
# SIGINT to force STDOUT be captured in file for verification
pkill -SIGINT scap-open;
sleep 1;

TEST=$(grep 'captured' ${OUTPUT_FILE} | sed "s/[^0-9]//g");
rm ${OUTPUT_FILE};
if [[ ${TEST} -ge "30" ]]; then
  exit 0
else
  exit 1
fi
