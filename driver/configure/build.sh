#!/bin/sh

#
# Copyright (C) 2023 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

SCRIPT=$(readlink -f "$0")
SCRIPT_DIR=$(dirname ${SCRIPT})

make -C ${SCRIPT_DIR} > ${SCRIPT_DIR}/build.log 2>&1
