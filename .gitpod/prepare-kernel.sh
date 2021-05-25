#!/bin/bash

set -xeuo pipefail

kernel_version=$1

script_dirname="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
outdir="${script_dirname}/_output/kernel"
config_file="${script_dirname}/.config-${kernel_version}"

kerneloutdir="${outdir}/linux-${kernel_version}"
rm -Rf $kerneloutdir

mkdir -p $outdir

curl -L -o "${outdir}/kernel.tar.gz" "https://git.kernel.org/torvalds/t/linux-${kernel_version}.tar.gz"

cd $outdir

tar -xvf kernel.tar.gz
cd "linux-${kernel_version}"

if [[ ! -f "${config_file}" ]]; then
    echo "${config_file} does not exist for this kernel"
    exit 1
fi

cp ${config_file} .config

make ARCH=x86_64 -j16
make modules_prepare
