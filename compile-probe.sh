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
DIR=`pwd`
if [ ! -d $DST  ];then
  mkdir $DST
fi

compilerBpfFun(){
	cd bpf
	make KERNELDIR=$src
	mv probe.o $DIR/$DST/$version.o
	make KERNELDIR=$src clean
}

compilerKernelModulesFun(){
	make KERNELDIR=$src
        mv $PROBE_NAME.ko $DIR/$DST/$version.ko
        make KERNELDIR=$src clean
}

for version in `ls /usr/src/kernels`
do
	cd $DIR/driver
	echo Compile probe for $version
	src=/usr/src/kernels/$version/
  compilerKernelModulesFun
	echo "$version"
  array=(${version//./ })

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
