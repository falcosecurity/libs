/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

/*=============================== FIXED CONSTRAINTS ===============================*/

/* These are some of the constraints we want to impose during our
 * store operations. One day these could become const global variables
 * that could be set by the userspace.
 */

/* Right now a `cgroup` pathname can have at most 6 components. */
#define MAX_CGROUP_PATH_POINTERS 6

/* Maximum length of `unix` socket path.
 * We can have a maximum of 108 characters plus the `\0` terminator.
 */
#define MAX_UNIX_SOCKET_PATH 108 + 1

/* Maximum number of `iovec` structures that we can analyze. */
#define MAX_IOVCNT 32

/* Maximum number of `pollfd` structures that we can analyze. */
#define MAX_POLLFD 16

/* Maximum number of charbuf pointers that we assume an array can have. */
#define MAX_CHARBUF_POINTERS 16

/* Proc name */
#define MAX_PROC_EXE 4096

/* Proc arguments or environment variables.
 * Must be always a power of 2 because we can also use it as a mask!
 */
#define MAX_PROC_ARG_ENV 4096

/* PATH_MAX supported by the operating system: 4096 */
#define MAX_PATH 4096

/*=============================== FIXED CONSTRAINTS ===============================*/

/*=============================== COMMON DEFINITIONS ===============================*/

/* Some auxiliary definitions we use during our store operations */

/* Conversion factors used in `setsockopt` val. */
#define SEC_FACTOR 1000000000
#define USEC_FACTOR 1000

/* Network components size. */
#define FAMILY_SIZE sizeof(u8)
#define IPV4_SIZE sizeof(u32)
#define IPV6_SIZE 16
#define PORT_SIZE sizeof(u16)
#define KERNEL_POINTER sizeof(u64)

/* This enum is used to tell network helpers if the connection outbound
 * or inbound
 */
enum connection_direction
{
	OUTBOUND = 0,
	INBOUND = 1,
};

/* This enum is used to tell poll helpers if we need requested or returned
 * events.
 */
enum poll_events_direction
{
	REQUESTED_EVENTS = 0,
	RETURNED_EVENTS = 1,
};

/*=============================== COMMON DEFINITIONS ===============================*/
