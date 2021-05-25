# Kernel development environment in Gitpod

This is a maintenance doc for the Falco Libs kernel development environment in Gitpod.

Here are some FAQs

## How to update kernel version

Open the `.gitpod.yaml` in the project root, then replace the old kernel version
as argument in both `prepare-kernel.sh` and `qemu.sh`.

Kernel versions can be looked up on [kernel.org](https://www.kernel.org/)

Once you have done that, create a proper configuration file, named `.config-<kernel-version>`
in this folder. This file can be created interactively by running `make menuconfig` in the
kernel root. You will likely need to enable eBPF support and Kernel debugging.

