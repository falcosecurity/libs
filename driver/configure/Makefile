#
# Copyright (C) 2023 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

testmod-y += test.o
obj-m += testmod.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
TOP := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(TOP) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(TOP) clean

install: all
	$(MAKE) -C $(KERNELDIR) M=$(TOP) modules_install
