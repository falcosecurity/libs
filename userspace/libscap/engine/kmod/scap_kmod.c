/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#define SCAP_HANDLE_T struct kmod_engine
#include "kmod.h"
#include "scap.h"
#include "driver_config.h"
#include "../../driver/ppm_ringbuffer.h"
#include "scap-int.h"
#include "scap_engine_util.h"
#include "ringbuffer/ringbuffer.h"
#include "strlcpy.h"
#include "strerror.h"

//#define NDEBUG
#include <assert.h>

static struct kmod_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct kmod_engine *engine = calloc(1, sizeof(struct kmod_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static void free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

static uint32_t get_max_consumers()
{
	uint32_t max;
	FILE *pfile = fopen("/sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/max_consumers", "r");
	if(pfile != NULL)
	{
		int w = fscanf(pfile, "%"PRIu32, &max);
		if(w == 0)
		{
			return 0;
		}

		fclose(pfile);
		return max;
	}

	return 0;
}

static int32_t enforce_into_kmod_buffer_bytes_dim(scap_t *handle, unsigned long buf_bytes_dim)
{
	const char* file_name = "/sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/g_buffer_bytes_dim";

	errno = 0;
	/* Here we check if the dimension provided by the kernel module is the same as the user-provided one. 
	 * In this way we can avoid writing under the `/sys/module/...` file.
	 */
	FILE *read_file = fopen(file_name, "r");
	if(read_file == NULL)
	{
		if (errno == ENOENT)
		{
			// It is most probably a wrong API version of the driver;
			// let the issue be gracefully managed during the api version check against the driver.
			return SCAP_SUCCESS;
		}
		return scap_errprintf(handle->m_lasterr, errno, "unable to open '%s'", file_name);
	}

	unsigned long kernel_buf_bytes_dim = 0;
	int ret = fscanf(read_file, "%lu", &kernel_buf_bytes_dim);
	if(ret != 1)
	{
		int err = errno;
		fclose(read_file);
		return scap_errprintf(handle->m_lasterr, err, "unable to read the syscall buffer dim from '%s'", file_name);
	}
	fclose(read_file);

	/* We have no to update the file writing on it, the dimension is the same. */
	if(kernel_buf_bytes_dim == buf_bytes_dim)
	{
		return SCAP_SUCCESS;
	}

	/* Fallback to write on the file if the dim is different */ 
	FILE *write_file = fopen(file_name, "w");
	if(write_file == NULL)
	{
		return scap_errprintf(handle->m_lasterr, errno, "unable to open '%s'. Probably the /sys/module filesystem is read-only", file_name);
	}

	if(fprintf(write_file, "%lu", buf_bytes_dim) < 0)
	{
		int err = errno;
		fclose(write_file);
		return scap_errprintf(handle->m_lasterr, err, "unable to write into /sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/g_buffer_bytes_dim");
	}

	fclose(write_file);
	return SCAP_SUCCESS;
}


int32_t scap_kmod_handle_tp_mask(struct scap_engine_handle engine, uint32_t op, uint32_t tp)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	uint32_t ioctl_op = op == SCAP_TP_MASK_SET ? PPM_IOCTL_ENABLE_TP : PPM_IOCTL_DISABLE_TP;
	if(ioctl(devset->m_devs[0].m_fd, ioctl_op, tp))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno,
			 "%s(%d) failed for tp %d",
			 __FUNCTION__, op, tp);
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_handle_ppm_sc_mask(struct scap_engine_handle engine, uint32_t op, uint32_t ppm_sc)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	int ioctl_op = op == SCAP_PPM_SC_MASK_SET ? PPM_IOCTL_ENABLE_SYSCALL : PPM_IOCTL_DISABLE_SYSCALL;
	// Find any syscall table entry that matches requested ppm_sc code
	for (int i = 0; i < SYSCALL_TABLE_SIZE; i++)
	{
		if (g_syscall_table[i].ppm_sc == ppm_sc)
		{
			if(ioctl(devset->m_devs[0].m_fd, ioctl_op, i))
			{
				ASSERT(false);
				return scap_errprintf(engine.m_handle->m_lasterr, errno,
					 "%s(%d) failed for syscall %d",
					 __FUNCTION__, op, i);
			}
		}
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_init(scap_t *handle, scap_open_args *oargs)
{
	uint32_t j = 0;
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_kmod_engine_params* params  = oargs->engine_params;
	char filename[SCAP_MAX_PATH_SIZE] = {0};
	uint32_t ndevs = 0;
	uint32_t ncpus;
	int32_t rc = 0;

	int mapped_len = 0;
	uint32_t all_scanned_devs = 0;
	uint64_t api_version = 0;
	uint64_t schema_version = 0;

	unsigned long single_buffer_dim = params->buffer_bytes_dim;
	if(check_buffer_bytes_dim(handle->m_lasterr, single_buffer_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}
	
	/* We need to enforce the buffer dim before opening the devices
	 * otherwise this dimension will be not set during the opening phase!
	 */
	if(enforce_into_kmod_buffer_bytes_dim(handle, single_buffer_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	ncpus = sysconf(_SC_NPROCESSORS_CONF);
	if(ncpus == -1)
	{
		return scap_errprintf(handle->m_lasterr, errno, "_SC_NPROCESSORS_CONF");
	}

	//
	// Find out how many devices we have to open, which equals to the number of CPUs
	//
	ndevs = sysconf(_SC_NPROCESSORS_ONLN);
	if(ndevs == -1)
	{
		return scap_errprintf(handle->m_lasterr, errno, "_SC_NPROCESSORS_ONLN");
	}

	rc = devset_init(&engine.m_handle->m_dev_set, ndevs, handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	//
	// Allocate the device descriptors.
	//
	mapped_len = single_buffer_dim * 2;

	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	for(j = 0, all_scanned_devs = 0; j < devset->m_ndevs && all_scanned_devs < ncpus; ++all_scanned_devs)
	{
		struct scap_device *dev = &devset->m_devs[j];

		//
		// Open the device
		//
		snprintf(filename, sizeof(filename), "%s/dev/" DRIVER_DEVICE_NAME "%d", scap_get_host_root(), all_scanned_devs);

		if((dev->m_fd = open(filename, O_RDWR | O_SYNC)) < 0)
		{
			if(errno == ENODEV)
			{
				//
				// This CPU is offline, so we just skip it
				//
				continue;
			}
			else if(errno == EBUSY)
			{
				uint32_t curr_max_consumers = get_max_consumers();
				return scap_errprintf(handle->m_lasterr, 0, "Too many consumers attached to device %s. Current value for /sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/max_consumers is '%"PRIu32"'.", filename, curr_max_consumers);
			}
			else
			{
				return scap_errprintf(handle->m_lasterr, errno, "error opening device %s. Make sure you have root credentials and that the " DRIVER_NAME " module is loaded", filename);
			}
		}

		// Set close-on-exec for the fd
		if (fcntl(dev->m_fd, F_SETFD, FD_CLOEXEC) == -1) {
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "Can not set close-on-exec flag for fd for device %s", filename);
		}

		// Check the API version reported
		if (ioctl(dev->m_fd, PPM_IOCTL_GET_API_VERSION, &api_version) < 0)
		{
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "Kernel module does not support PPM_IOCTL_GET_API_VERSION");
		}
		// Make sure all devices report the same API version
		if (handle->m_api_version != 0 && handle->m_api_version != api_version)
		{
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "API version mismatch: device %s reports API version %llu.%llu.%llu, expected %llu.%llu.%llu",
				 filename,
				 PPM_API_VERSION_MAJOR(api_version),
				 PPM_API_VERSION_MINOR(api_version),
				 PPM_API_VERSION_PATCH(api_version),
				 PPM_API_VERSION_MAJOR(handle->m_api_version),
				 PPM_API_VERSION_MINOR(handle->m_api_version),
				 PPM_API_VERSION_PATCH(handle->m_api_version)
			);
		}
		// Set the API version from the first device
		// (for subsequent devices it's a no-op thanks to the check above)
		handle->m_api_version = api_version;

		// Check the schema version reported
		if (ioctl(dev->m_fd, PPM_IOCTL_GET_SCHEMA_VERSION, &schema_version) < 0)
		{
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "Kernel module does not support PPM_IOCTL_GET_SCHEMA_VERSION");
		}
		// Make sure all devices report the same schema version
		if (handle->m_schema_version != 0 && handle->m_schema_version != schema_version)
		{
			return scap_errprintf(handle->m_lasterr, 0, "Schema version mismatch: device %s reports schema version %llu.%llu.%llu, expected %llu.%llu.%llu",
				 filename,
				 PPM_API_VERSION_MAJOR(schema_version),
				 PPM_API_VERSION_MINOR(schema_version),
				 PPM_API_VERSION_PATCH(schema_version),
				 PPM_API_VERSION_MAJOR(handle->m_schema_version),
				 PPM_API_VERSION_MINOR(handle->m_schema_version),
				 PPM_API_VERSION_PATCH(handle->m_schema_version)
			);
		}
		// Set the schema version from the first device
		// (for subsequent devices it's a no-op thanks to the check above)
		handle->m_schema_version = schema_version;

		//
		// Map the ring buffer
		//
		dev->m_buffer = (char*)mmap(0,
					    mapped_len,
					    PROT_READ,
					    MAP_SHARED,
					    dev->m_fd,
					    0);

		if(dev->m_buffer == MAP_FAILED)
		{
			int err = errno;
			// we cleanup this fd and then we let scap_close() take care of the other ones
			close(dev->m_fd);

			return scap_errprintf(handle->m_lasterr, err, "error mapping the ring buffer for device %s. (If you get memory allocation errors try to reduce the buffer dimension)", filename);
		}
		dev->m_buffer_size = single_buffer_dim;
		dev->m_mmap_size = mapped_len;

		//
		// Map the ppm_ring_buffer_info that contains the buffer pointers
		//
		dev->m_bufinfo = (struct ppm_ring_buffer_info*)mmap(0,
								    sizeof(struct ppm_ring_buffer_info),
								    PROT_READ | PROT_WRITE,
								    MAP_SHARED,
								    dev->m_fd,
								    0);

		if(dev->m_bufinfo == MAP_FAILED)
		{
			int err = errno;

			// we cleanup this fd and then we let scap_close() take care of the other ones
			munmap(dev->m_buffer, mapped_len);
			close(dev->m_fd);

			return scap_errprintf(handle->m_lasterr, err, "error mapping the ring buffer info for device %s. (If you get memory allocation errors try to reduce the buffer dimension)", filename);
		}
		dev->m_bufinfo_size = sizeof(struct ppm_ring_buffer_info);

		++j;
	}

	/* Set interesting Syscalls */
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		uint32_t op = oargs->ppm_sc_of_interest.ppm_sc[ppm_sc] ? SCAP_PPM_SC_MASK_SET : SCAP_PPM_SC_MASK_UNSET;
		scap_kmod_handle_ppm_sc_mask(engine, op, ppm_sc);
	}

	/* Store interesting Tracepoints */
	memcpy(&engine.m_handle->open_tp_set, &oargs->tp_of_interest, sizeof(interesting_tp_set));

	return SCAP_SUCCESS;
}

int32_t scap_kmod_close(struct scap_engine_handle engine)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;

	devset_free(devset);

	return SCAP_SUCCESS;
}

int32_t scap_kmod_next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	return ringbuffer_next(&engine.m_handle->m_dev_set, pevent, pcpuid);
}

uint32_t scap_kmod_get_n_devs(struct scap_engine_handle engine)
{
	return engine.m_handle->m_dev_set.m_ndevs;
}

uint64_t scap_kmod_get_max_buf_used(struct scap_engine_handle engine)
{
	return ringbuffer_get_max_buf_used(&engine.m_handle->m_dev_set);
}

//
// Return the number of dropped events for the given handle
//
int32_t scap_kmod_get_stats(struct scap_engine_handle engine, scap_stats* stats)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	uint32_t j;

	for(j = 0; j < devset->m_ndevs; j++)
	{
		struct scap_device *dev = &devset->m_devs[j];
		stats->n_evts += dev->m_bufinfo->n_evts;
		stats->n_drops_buffer += dev->m_bufinfo->n_drops_buffer;
		stats->n_drops_buffer_clone_fork_enter += dev->m_bufinfo->n_drops_buffer_clone_fork_enter;
		stats->n_drops_buffer_clone_fork_exit += dev->m_bufinfo->n_drops_buffer_clone_fork_exit;
		stats->n_drops_buffer_execve_enter += dev->m_bufinfo->n_drops_buffer_execve_enter;
		stats->n_drops_buffer_execve_exit += dev->m_bufinfo->n_drops_buffer_execve_exit;
		stats->n_drops_buffer_connect_enter += dev->m_bufinfo->n_drops_buffer_connect_enter;
		stats->n_drops_buffer_connect_exit += dev->m_bufinfo->n_drops_buffer_connect_exit;
		stats->n_drops_buffer_open_enter += dev->m_bufinfo->n_drops_buffer_open_enter;
		stats->n_drops_buffer_open_exit += dev->m_bufinfo->n_drops_buffer_open_exit;
		stats->n_drops_buffer_dir_file_enter += dev->m_bufinfo->n_drops_buffer_dir_file_enter;
		stats->n_drops_buffer_dir_file_exit += dev->m_bufinfo->n_drops_buffer_dir_file_exit;
		stats->n_drops_buffer_other_interest_enter += dev->m_bufinfo->n_drops_buffer_other_interest_enter;
		stats->n_drops_buffer_other_interest_exit += dev->m_bufinfo->n_drops_buffer_other_interest_exit;
		stats->n_drops_pf += dev->m_bufinfo->n_drops_pf;
		stats->n_drops += dev->m_bufinfo->n_drops_buffer +
				  dev->m_bufinfo->n_drops_pf;
		stats->n_preemptions += dev->m_bufinfo->n_preemptions;
}

return SCAP_SUCCESS;
}

//
// Stop capturing the events
//
int32_t scap_kmod_stop_capture(struct scap_engine_handle engine)
{
	/* Disable all tracepoints */
	int ret = SCAP_SUCCESS;
	for (int i = 0; i < TP_VAL_MAX && ret == SCAP_SUCCESS; i++)
	{
		ret = scap_kmod_handle_tp_mask(engine, SCAP_TP_MASK_UNSET, i);
	}
	return ret;
}

//
// Start capturing the events
//
int32_t scap_kmod_start_capture(struct scap_engine_handle engine)
{
	struct kmod_engine* handle = engine.m_handle;

	/* Enable requested tracepoints */
	int ret = SCAP_SUCCESS;
	for (int i = 0; i < TP_VAL_MAX && ret == SCAP_SUCCESS; i++)
	{
		if (handle->open_tp_set.tp[i])
		{
			ret = scap_kmod_handle_tp_mask(engine, SCAP_TP_MASK_SET, i);
		}
	}

	return ret;
}

static int32_t scap_kmod_set_dropping_mode(struct scap_engine_handle engine, int request, uint32_t sampling_ratio)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	if(devset->m_ndevs)
	{
		ASSERT((request == PPM_IOCTL_ENABLE_DROPPING_MODE &&
			((sampling_ratio == 1)  ||
				(sampling_ratio == 2)  ||
				(sampling_ratio == 4)  ||
				(sampling_ratio == 8)  ||
				(sampling_ratio == 16) ||
				(sampling_ratio == 32) ||
				(sampling_ratio == 64) ||
				(sampling_ratio == 128))) || (request == PPM_IOCTL_DISABLE_DROPPING_MODE));

		if(ioctl(devset->m_devs[0].m_fd, request, sampling_ratio))
		{
			ASSERT(false);
			return scap_errprintf(engine.m_handle->m_lasterr, errno, "%s, request %d for sampling ratio %u",
					__FUNCTION__, request, sampling_ratio);
		}
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_enable_tracers_capture(struct scap_engine_handle engine)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	if(devset->m_ndevs)
	{
		{
			if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_TRACERS_CAPTURE))
			{
				ASSERT(false);
				return scap_errprintf(engine.m_handle->m_lasterr, errno, "%s failed", __FUNCTION__);
			}
		}
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_stop_dropping_mode(struct scap_engine_handle engine)
{
	return scap_kmod_set_dropping_mode(engine, PPM_IOCTL_DISABLE_DROPPING_MODE, 0);
}

int32_t scap_kmod_start_dropping_mode(struct scap_engine_handle engine, uint32_t sampling_ratio)
{
	return scap_kmod_set_dropping_mode(engine, PPM_IOCTL_ENABLE_DROPPING_MODE, sampling_ratio);
}

int32_t scap_kmod_set_snaplen(struct scap_engine_handle engine, uint32_t snaplen)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_SNAPLEN, snaplen))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_set_snaplen failed");
	}

	uint32_t j;

	//
	// Force a flush of the read buffers, so we don't capture events with the old snaplen
	//
	for(j = 0; j < devset->m_ndevs; j++)
	{
		ringbuffer_readbuf(&devset->m_devs[j],
				   &devset->m_devs[j].m_sn_next_event,
				   &devset->m_devs[j].m_sn_len);

		devset->m_devs[j].m_sn_len = 0;
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_enable_dynamic_snaplen(struct scap_engine_handle engine)
{
	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(engine.m_handle->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_enable_dynamic_snaplen failed");
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_disable_dynamic_snaplen(struct scap_engine_handle engine)
{
	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(engine.m_handle->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_disable_dynamic_snaplen failed");
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	if(ioctl(engine.m_handle->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_N_TRACEPOINT_HIT, ret))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_get_n_tracepoint_hit failed");
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_set_fullcapture_port_range(struct scap_engine_handle engine, uint16_t range_start, uint16_t range_end)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	//
	// Encode the port range
	//
	uint32_t arg = (range_end << 16) + range_start;

	//
	// Beam the value down to the module
	//
	if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE, arg))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_set_fullcapture_port_range failed");
	}

	uint32_t j;

	//
	// Force a flush of the read buffers, so we don't capture events with the old snaplen
	//
	for(j = 0; j < devset->m_ndevs; j++)
	{
		ringbuffer_readbuf(&devset->m_devs[j],
				   &devset->m_devs[j].m_sn_next_event,
				   &devset->m_devs[j].m_sn_len);

		devset->m_devs[j].m_sn_len = 0;
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_set_statsd_port(struct scap_engine_handle engine, const uint16_t port)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	//
	// Beam the value down to the module
	//
	if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_STATSD_PORT, port))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr,
			 errno, "scap_set_statsd_port: ioctl failed");
	}

	uint32_t j;

	//
	// Force a flush of the read buffers, so we don't
	// capture events with the old snaplen
	//
	for(j = 0; j < devset->m_ndevs; j++)
	{
		ringbuffer_readbuf(&devset->m_devs[j],
				   &devset->m_devs[j].m_sn_next_event,
				   &devset->m_devs[j].m_sn_len);

		devset->m_devs[j].m_sn_len = 0;
	}

	return SCAP_SUCCESS;
}

static int32_t unsupported_config(struct scap_engine_handle engine, const char* msg)
{
	struct kmod_engine* handle = engine.m_handle;

	strlcpy(handle->m_lasterr, msg, SCAP_LASTERR_SIZE);
	return SCAP_FAILURE;
}

static int32_t configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	switch(setting)
	{
	case SCAP_SAMPLING_RATIO:
		if(arg2 == 0)
		{
			return scap_kmod_stop_dropping_mode(engine);
		}
		else
		{
			return scap_kmod_start_dropping_mode(engine, arg1);
		}
	case SCAP_TRACERS_CAPTURE:
		if(arg1 == 0)
		{
			return unsupported_config(engine, "Tracers cannot be disabled once enabled");
		}
		return scap_kmod_enable_tracers_capture(engine);
	case SCAP_SNAPLEN:
		return scap_kmod_set_snaplen(engine, arg1);
	case SCAP_PPM_SC_MASK:
		return scap_kmod_handle_ppm_sc_mask(engine, arg1, arg2);
	case SCAP_TP_MASK:
		return scap_kmod_handle_tp_mask(engine, arg1, arg2);
	case SCAP_DYNAMIC_SNAPLEN:
		if(arg1 == 0)
		{
			return scap_kmod_disable_dynamic_snaplen(engine);
		}
		else
		{
			return scap_kmod_enable_dynamic_snaplen(engine);
		}
	case SCAP_FULLCAPTURE_PORT_RANGE:
		return scap_kmod_set_fullcapture_port_range(engine, arg1, arg2);
	case SCAP_STATSD_PORT:
		return scap_kmod_set_statsd_port(engine, arg1);
	default:
	{
		char msg[256];
		snprintf(msg, sizeof(msg), "Unsupported setting %d (args %lu, %lu)", setting, arg1, arg2);
		return unsupported_config(engine, msg);
	}
	}
}

static int32_t scap_kmod_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr)
{
	struct kmod_engine* kmod_engine = engine.m_handle;
	if(*procinfo_p == NULL)
	{
		if(scap_alloc_proclist_info(procinfo_p, SCAP_DRIVER_PROCINFO_INITIAL_SIZE, lasterr) == false)
		{
			return SCAP_FAILURE;
		}
	}

	int ioctlres = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_PROCLIST, *procinfo_p);
	if(ioctlres)
	{
		if(errno == ENOSPC)
		{
			if(scap_alloc_proclist_info(procinfo_p, (*procinfo_p)->n_entries + 256, kmod_engine->m_lasterr) == false)
			{
				return SCAP_FAILURE;
			}
			else
			{
				return scap_kmod_get_threadlist(engine, procinfo_p, lasterr);
			}
		}
		else
		{
			return scap_errprintf(kmod_engine->m_lasterr, errno, "Error calling PPM_IOCTL_GET_PROCLIST");
		}
	}

	return SCAP_SUCCESS;
}


static int32_t scap_kmod_get_vpid(struct scap_engine_handle engine, uint64_t pid, int64_t* vpid)
{
	struct kmod_engine *kmod_engine = engine.m_handle;
	*vpid = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_VPID, pid);

	if(*vpid == -1)
	{
		ASSERT(false);
		return scap_errprintf(kmod_engine->m_lasterr, errno, "ioctl to get vpid failed");
	}

	return SCAP_SUCCESS;
}

static int32_t scap_kmod_get_vtid(struct scap_engine_handle engine, uint64_t tid, int64_t* vtid)
{
	struct kmod_engine *kmod_engine = engine.m_handle;
	*vtid = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_VTID, tid);

	if(*vtid == -1)
	{
		ASSERT(false);
		return scap_errprintf(kmod_engine->m_lasterr, errno, "ioctl to get vtid failed");
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_getpid_global(struct scap_engine_handle engine, int64_t* pid, char* error)
{
	struct kmod_engine *kmod_engine = engine.m_handle;
	*pid = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_CURRENT_PID);
	if(*pid == -1)
	{
		ASSERT(false);
		return scap_errprintf(kmod_engine->m_lasterr, errno, "ioctl to get pid failed");
	}

	return SCAP_SUCCESS;
}

struct scap_vtable scap_kmod_engine = {
	.name = KMOD_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = scap_kmod_init,
	.free_handle = free_handle,
	.close = scap_kmod_close,
	.next = scap_kmod_next,
	.start_capture = scap_kmod_start_capture,
	.stop_capture = scap_kmod_stop_capture,
	.configure = configure,
	.get_stats = scap_kmod_get_stats,
	.get_n_tracepoint_hit = scap_kmod_get_n_tracepoint_hit,
	.get_n_devs = scap_kmod_get_n_devs,
	.get_max_buf_used = scap_kmod_get_max_buf_used,
	.get_threadlist = scap_kmod_get_threadlist,
	.get_vpid = scap_kmod_get_vpid,
	.get_vtid = scap_kmod_get_vtid,
	.getpid_global = scap_kmod_getpid_global,
};
