/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/maps_getters.h>
#include <helpers/base/read_from_task.h>
#include <driver/ppm_flag_helpers.h>

/* All the functions that are called in bpf to extract parameters
 * start with the `extract` prefix.
 */

/////////////////////////
// SYSCALL ARGUMENTS EXTRACION
////////////////////////

/**
 * @brief Extact a specific syscall argument
 *
 * @param regs pointer to the strcut where we find the arguments
 * @param idx index of the argument to extract
 * @return generic unsigned long value that can be a pointer to the arg
 * or directly the value, it depends on the type of arg.
 */
static __always_inline unsigned long extract__syscall_argument(struct pt_regs *regs, int idx)
{
	unsigned long arg;
	switch(idx)
	{
	case 0:
		arg = PT_REGS_PARM1_CORE_SYSCALL(regs);
		break;
	case 1:
		arg = PT_REGS_PARM2_CORE_SYSCALL(regs);
		break;
	case 2:
		arg = PT_REGS_PARM3_CORE_SYSCALL(regs);
		break;
	case 3:
		arg = PT_REGS_PARM4_CORE_SYSCALL(regs);
		break;
	case 4:
		arg = PT_REGS_PARM5_CORE_SYSCALL(regs);
		break;
	case 5:
		/* Not defined in libbpf, look at `definitions_helpers.h` */
		arg = PT_REGS_PARM6_CORE_SYSCALL(regs);
		break;
	default:
		arg = 0;
	}

	return arg;
}

/////////////////////////
// GENERIC EXTRACTION
////////////////////////

/**
 * @brief Extract `len_to_read` bytes from the pointer.
 *
 * The `dest` pointer usually is the stack or the auxmap.
 * If it is the auxmap we don't have to increment the payload_pos
 * since we are using the map as a scratch space!
 *
 * Please note: in case of failure the content of `dest` is not
 * changed so we don't have to manage the return value, we have only
 * to pass an empty value by default
 *
 * @param dest pointer to the destination buffer.
 * @param len_to_read number of bytes to be read.
 * @param src pointer to the source buffer.
 * @return return code of `bpf_probe_read`
 */
static __always_inline int extract__bytebuf_from_pointer(void *dest, unsigned long len_to_read, void *src)
{
	return bpf_probe_read(dest, SAFE_ACCESS(len_to_read), src);
}

///////////////////////////
// ENCODE DEVICE NUMBER
///////////////////////////

/**
 * @brief Encode device number with `MAJOR` and `MINOR` MACRO.
 *
 * Please note: **Used only inside this file**.
 *
 * @param dev device number extracted directly from the kernel.
 * @return encoded device number.
 */
static __always_inline dev_t encode_dev(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

///////////////////////////
// FILE EXTRACION
///////////////////////////

/**
 * @brief Return `file` struct from a file descriptor.
 *
 * @param file_descriptor generic file descriptor.
 * @return struct file* pointer to the `struct file` associated with the
 * file descriptor. Return a NULL pointer in case of failure.
 */
static __always_inline struct file *extract__file_struct_from_fd(s32 file_descriptor)
{
	struct file *f = NULL;
	if(file_descriptor > 0)
	{
		struct file **fds;
		struct task_struct *task = get_current_task();
		READ_TASK_FIELD_INTO(&fds, task, files, fdt, fd);
		bpf_probe_read_kernel(&f, sizeof(struct file *), &fds[file_descriptor]);
	}
	return f;
}

/**
 * \brief Extract the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @param ino pointer to the inode number we have to fill.
 */
static __always_inline void extract__ino_from_fd(s32 fd, u64 *ino)
{
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		return;
	}

	BPF_CORE_READ_INTO(ino, f, f_inode, i_ino);
}

/**
 * \brief Extract the device number and the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @param dev pointer to the device number we have to fill.
 * @param ino pointer to the inode number we have to fill.
 */
static __always_inline void extract__dev_and_ino_from_fd(s32 fd, dev_t *dev, u64 *ino)
{
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		return;
	}

	BPF_CORE_READ_INTO(dev, f, f_inode, i_sb, s_dev);
	*dev = encode_dev(*dev);
	BPF_CORE_READ_INTO(ino, f, f_inode, i_ino);
}
