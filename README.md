# falcosecurity/libs

As per the [OSS Libraries Contribution Plan](https://github.com/falcosecurity/falco/blob/master/proposals/2021019-libraries-donation.md), this repository has been chosen to be the new home for **libsinsp**, **libscap**, the **kernel module driver** and the **eBPF driver sources**.

## Kernel module and BPF Development in Gitpod

[![Gitpod ready-to-code](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/falcosecurity/libs)

The Falco libraries are used to interact with the Linux kernel via either the Falco [Kernel Module](https://github.com/falcosecurity/libs/tree/master/driver) or the [eBPF probe](https://github.com/falcosecurity/libs/tree/master/driver/bpf).

Contributors might find hard to maintain and use a development environment suitable for Kernel development when they need
to make changes to those components from time to time.

To make that easy, here we have a complete and ready to use environment running as a Gitpod workspace.

After clicking on the button above, you will have an opened VSCode in your browser pointing to this repo.

It will be already configured with a qemu VM running a very recent kernel that was just built on the fly for you.

Then you can build the BPF probe as follows:

```bash
mkdir build
cd build
cmake -DBUILD_BPF=On ..
cd ..
cd driver/bpf
make KERNELDIR=$GITPOD_REPO_ROOT/.gitpod/_output/kernel/linux-5.13-rc3
```

Once you have that, you will need to copy the BPF probe into it via `scp`, password is `root`:

```
scp -P 2222 probe.o root@127.0.0.1:/tmp/probe.o
```

You can now SSH into the machine and test your probe against Falco or against your own consumer, password is `root`:

```
ssh -p 2222 root@127.0.0.1
```
