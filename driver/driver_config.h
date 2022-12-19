/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#pragma once

#define PROBE_VERSION "0.1.1dev"

#define PROBE_NAME "kindling-falcolib-probe"

#define PROBE_DEVICE_NAME "kindling-falcolib"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME PROBE_NAME
#endif
