#!/bin/bash

# file structure:
#		- driver
# 			- Makefile (kernel modules)
#			- *.h, *.c
#			- bpf
#				- *.h, *.c
#				- Makefile (bpf probe)
#		- compile-probe.sh: script for compiling
#   - probe: contains all probes after compiling
PROBE_NAME=kindling-falcolib-probe
DST=kindling-falcolib-probe
DIR=$(pwd)
if [ ! -d $DST ]; then
  mkdir $DST
fi

compilerBpfFun() {
  cd bpf
  make KERNELDIR=$src
  mv probe.o $DIR/$DST/$version.o
  make KERNELDIR=$src clean
}

compilerKernelModulesFun() {
  make KERNELDIR=$src
  mv $PROBE_NAME.ko $DIR/$DST/$version.ko
  make KERNELDIR=$src clean
}

for version in $(ls /lib/modules); do
  array=(${version//./ })
  version3=${array[2]}
  if [[ ${array[2]} =~ "-" ]]; then
    versionSmall=(${version3//-/ })
    if [ ${array[0]} -eq 3 ] && [ ${array[1]} -eq 10 ] && [ ${versionSmall[0]} == "0" ] && [ ${versionSmall[1]} -lt 327 ]; then
      rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc
    elif [ ${array[0]} -ge 5 ]; then
      rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-8 /usr/bin/gcc
    else
      rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-5 /usr/bin/gcc
    fi
  fi
  cd $DIR/driver
  echo Compile probe for $version
  src=/lib/modules/$version/build
  compilerKernelModulesFun
  echo "$version"

  if [ ${array[0]} -ge 5 ]; then
    compilerBpfFun
  fi
  if [ ${array[0]} -ge 4 ] && [ ${array[1]} -ge 14 ]; then
    compilerBpfFun
  fi
  if [ ${array[0]} -eq 3 ] && [ ${array[1]} -eq 10 ] && [ ${array[2]} == "0-957" ]; then
    compilerBpfFun
  fi
  if [ ${array[0]} -eq 3 ] && [ ${array[1]} -eq 10 ] && [ ${array[2]} == "0-1062" ]; then
    compilerBpfFun
  fi
  if [ ${array[0]} -eq 3 ] && [ ${array[1]} -eq 10 ] && [ ${array[2]} == "0-1127" ]; then
    compilerBpfFun
  fi
  if [ ${array[0]} -eq 3 ] && [ ${array[1]} -eq 10 ] && [ ${array[2]} == "0-1160" ]; then
    compilerBpfFun
  fi

done
