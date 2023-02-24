#
# Copyright (C) 2021 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

always-y += probe.o
# kept for compatibility with kernels < 5.11
always = $(always-y)

LLC ?= llc
CLANG ?= clang

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# Filter out -fmacro-prefix-map from KBUILD_CPPFLAGS, because that option
# is specified in some kernel versions, but not supported on the version
# of clang (7) that we use in the agent image.
FILTERED_KBUILD_CPPFLAGS=$(shell echo " ${KBUILD_CPPFLAGS} " | sed 's/ -fmacro-prefix-map[^ ]* / /')

# DEBUG = -DBPF_DEBUG
CPU = -DCPU_ANALYSIS
all:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

clean:
	$(MAKE) -C $(KERNELDIR) M=$$PWD clean
	@rm -f *~

$(obj)/probe.o: $(src)/probe.c \
		$(src)/bpf_helpers.h \
		$(src)/filler_helpers.h \
		$(src)/fillers.h \
		$(src)/maps.h \
		$(src)/plumbing_helpers.h \
		$(src)/quirks.h \
		$(src)/ring_helpers.h \
		$(src)/types.h
	$(CLANG) $(LINUXINCLUDE) \
		$(FILTERED_KBUILD_CPPFLAGS) \
		$(KBUILD_EXTRA_CPPFLAGS) \
		$(DEBUG) \
		$(CPU) \
		-D__KERNEL__ \
		-D__BPF_TRACING__ \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-fno-jump-tables \
		-fno-stack-protector \
		-Wno-tautological-compare \
		-Wno-incompatible-pointer-types-discards-qualifiers \
		-O2 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	$(LLC) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)
