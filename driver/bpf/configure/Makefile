# SPDX-License-Identifier: GPL-2.0-only OR MIT
#
# Copyright (C) 2023 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

always-y += test.o
# kept for compatibility with kernels < 5.11
always = $(always-y)

LLC ?= llc
CLANG ?= clang

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# -fmacro-prefix-map is not supported on version of clang older than 10
# so remove it if necessary.
IS_CLANG_OLDER_THAN_10 := $(shell expr `$(CLANG) -dumpversion | cut -f1 -d.` \<= 10)
ifeq ($(IS_CLANG_OLDER_THAN_10), 1)
	KBUILD_CPPFLAGS := $(filter-out -fmacro-prefix-map=%,$(KBUILD_CPPFLAGS))
endif

all:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

clean:
	$(MAKE) -C $(KERNELDIR) M=$$PWD clean
	@rm -f *~

$(obj)/test.o: $(src)/test.c
	$(CLANG) $(LINUXINCLUDE) \
		$(KBUILD_CPPFLAGS) \
		$(KBUILD_EXTRA_CPPFLAGS) \
		-D__KERNEL__ \
		-D__BPF_TRACING__ \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-fno-jump-tables \
		-fno-stack-protector \
		-Wno-tautological-compare \
		-Wno-unknown-attributes \
		-O2 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	$(LLC) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)
