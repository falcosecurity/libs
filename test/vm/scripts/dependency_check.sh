#!/bin/bash

set -eou pipefail

echo "Run dependency check";

for prog in bash time ssh scp tar vagrant virtualbox go docker
do
    command -v $prog >/dev/null 2>&1 || { echo >&2 "$prog is not installed, exiting ..."; exit 1; }
    echo "$prog is installed"
done

if [[ $(uname -s) == "Linux" ]]; then
    if [[ $(uname -m) != "x86_64" ]]; then
        echo "Support only for x86_64, exiting ..."
        exit 1;
    fi;

    if test "$( grep -E 'vmx|svm' /proc/cpuinfo | wc -l )" -gt "0"; then
        echo "Hardware virtualization in BIOS satisfied";
    else
        echo "Hardware virtualization in BIOS is not satisfied, check with cmd \"grep -E 'vmx|svm' /proc/cpuinfo | wc -l\", exiting ...";
        exit 1;
    fi;

    if test "$( lsmod | grep vboxdrv | wc -l )" -gt "0"; then
        echo "vboxdrv kernel module is loaded";
    else
        echo "vboxdrv kernel module is not loaded, check with cmd \"lsmod | grep vboxdrv | wc -l\", exiting ...";
        exit 1;
    fi;
elif [[ $(uname -s) == "Darwin" ]]; then
    if [[ $(uname -m) != "x86_64" ]]; then
        echo "Apple silicon is not yet supported, exiting ..."
        exit 1;
    fi;

    if test "$( sysctl -a | grep -o VMX | wc -l )" -gt "0"; then
        echo "Hardware virtualization in BIOS satisfied";
    else
        echo "Hardware virtualization in BIOS is not satisfied, check with cmd \"sysctl -a | grep -o VMX | wc -l\", exiting ...";
        exit 1;
    fi;
fi;
