#!/bin/bash

set -xeuo pipefail

kernel_version=$1

script_dirname="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
outdir="${script_dirname}/_output"

sudo qemu-system-x86_64 -kernel "${outdir}/kernel/linux-${kernel_version}/arch/x86/boot/bzImage" \
-boot c -m 2049M -hda "${outdir}/rootfs/hirsute-server-cloudimg-amd64.img" \
-net user \
-smp 8 \
-append "root=/dev/sda rw console=ttyS0,115200 acpi=off nokaslr" \
-nic user,hostfwd=tcp::2222-:22 \
-serial mon:stdio -display none
