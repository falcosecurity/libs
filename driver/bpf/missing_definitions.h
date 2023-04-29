/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
struct ovl_entry {
	union {
		struct {
			unsigned long has_upper;
			bool opaque;
		};
		struct rcu_head rcu;
	};
	unsigned numlower;
	struct path lowerstack[];
};
#else
struct ovl_entry {
	union {
		struct {
			unsigned long flags;
		};
		struct rcu_head rcu;
	};
	unsigned numlower;
	//struct ovl_path lowerstack[];
};

enum ovl_entry_flag {
	OVL_E_UPPER_ALIAS,
	OVL_E_OPAQUE,
	OVL_E_CONNECTED,
};
#endif
