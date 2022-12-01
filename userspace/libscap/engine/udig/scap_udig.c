#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#define SCAP_HANDLE_T struct udig_engine

#include "udig.h"
#include "scap.h"
#include "scap-int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "ringbuffer/ringbuffer.h"
#include "engine/noop/noop.h"
#include "strerror.h"
#include "strlcpy.h"

#define PPM_PORT_STATSD 8125

#ifndef UDIG_INSTRUMENTER
#define ud_shm_open shm_open
#else
int ud_shm_open(const char *name, int flag, mode_t mode);
#endif

///////////////////////////////////////////////////////////////////////////////
// The following 2 function map the ring buffer and the ring buffer 
// descriptors into the address space of this process.
// This is the buffer that will be consumed by scap.
///////////////////////////////////////////////////////////////////////////////
int32_t udig_alloc_ring(void* ring_id, 
	uint8_t** ring, 
	unsigned long *ringsize,
	char *error)
{
	int* ring_fd = (int*)ring_id;

	//
	// First, try to open an existing ring
	//
	*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_RDWR, 0);
	if(*ring_fd >= 0)
	{
		//
		// Existing ring found, find out the size
		//
		struct stat rstat;
		if(fstat(*ring_fd, &rstat) < 0)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring fstat error: %s\n", strerror(errno));
			return SCAP_FAILURE;
		}

		*ringsize = rstat.st_size;
	}
	else
	{
		//
		// No ring found, allocate a new one.
		// Note that, according to the man page, the content of the buffer will
		// be initialized to 0.
		//
		*ringsize = UDIG_RING_SIZE;

		*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_CREAT | O_RDWR, 
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_fd >= 0)
		{
			//
			// For some reason, shm_open doesn't always set the write flag for
			// 'group' and 'other'. Fix it here.
			//
			fchmod(*ring_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

			if(ftruncate(*ring_fd, *ringsize) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring ftruncate error: %s\n", strerror(errno));
				close(*ring_fd);
				return SCAP_FAILURE;
			}
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring shm_open error: %s\n", strerror(errno));
			return SCAP_FAILURE;
		}
	}

	if(check_buffer_bytes_dim(error, *ringsize) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Map the ring. This is a multi-step process because we want to map two
	// consecutive copies of the same memory to reuse the driver fillers, which
	// expect to be able to go past the end of the ring.
	// First of all, allocate enough space for the 2 copies. This allows us 
	// to find an area of consecutive memory that is big enough.
	//
	uint8_t* buf1 = (uint8_t*)mmap(NULL, (*ringsize) * 2, 
		PROT_WRITE, MAP_SHARED,
		*ring_fd, 0);
	if(buf1 == MAP_FAILED)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map double buffer\n");
		close(*ring_fd);
		return SCAP_FAILURE;
	}

	// Map the first ring copy at exactly the beginning of the previously
	// allocated area, forcing it with MAP_FIXED.
	*ring = (uint8_t*)mmap(buf1, *ringsize, 
		PROT_WRITE, MAP_SHARED | MAP_FIXED, *ring_fd, 0);
	if(*ring != buf1)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring mmap 2 error: %s\n", strerror(errno));
		close(*ring_fd);
		return SCAP_FAILURE;
	}

	// Map the second ring copy just after the end of the first one.
	uint8_t* buf2 = buf1 + *ringsize;
	uint8_t* ring2 = (uint8_t*)mmap(buf2, *ringsize, 
		PROT_WRITE, MAP_SHARED | MAP_FIXED, *ring_fd, 0);
	if(ring2 != buf2)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map second copy of buffer, needed %p, obtained %p, base=%p\n", 
			buf2, ring2, buf1);
		close(*ring_fd);
		munmap(*ring, *ringsize);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t udig_alloc_ring_descriptors(void* ring_descs_id, 
	struct ppm_ring_buffer_info** ring_info, 
	struct udig_ring_buffer_status** ring_status,
	char *error)
{
	int* ring_descs_fd = (int*)ring_descs_id;
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);

	//
	// First, try to open an existing ring
	//
	*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_RDWR, 0);
	if(*ring_descs_fd < 0)
	{
		//
		// No existing ring file found in /dev/shm, create a new one.
		//
		*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_CREAT | O_RDWR | O_EXCL, 
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_descs_fd >= 0)
		{
			//
			// For some reason, shm_open doesn't always set the write flag for
			// 'group' and 'other'. Fix it here.
			//
			fchmod(*ring_descs_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

			//
			// Ring created, set its size
			//
			if(ftruncate(*ring_descs_fd, mem_size) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors ftruncate error: %s\n", strerror(errno));
				close(*ring_descs_fd);
				shm_unlink(UDIG_RING_DESCS_SM_FNAME);
				return SCAP_FAILURE;
			}
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors shm_open error: %s\n", strerror(errno));
			shm_unlink(UDIG_RING_DESCS_SM_FNAME);
			return SCAP_FAILURE;
		}
	}

	//
	// Map the memory
	//
	uint8_t* descs = (uint8_t*)mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, 
		*ring_descs_fd, 0);
	if(descs == MAP_FAILED)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map descriptors\n");
		close(*ring_descs_fd);
		return SCAP_FAILURE;
	}

	*ring_info = (struct ppm_ring_buffer_info*)descs;

	//
	// Locate the ring buffer status object
	//
	*ring_status = (struct udig_ring_buffer_status*)((uint64_t)*ring_info + 
		sizeof(struct ppm_ring_buffer_info));

	//
	// If we are the original creators of the shared buffer, proceed to
	// initialize it.
	// Note that, according to the man page of ud_shm_open, we are guaranteed that 
	// the content of the buffer will initiually be initialized to 0.
	//
	if(__sync_bool_compare_and_swap(&((*ring_status)->m_initialized), 0, 1))
	{
		(*ring_status)->m_buffer_lock = 0;
		(*ring_status)->m_capturing_pid = 0;
		(*ring_status)->m_stopped = 0;
		(*ring_status)->m_last_print_time.tv_sec = 0;
		(*ring_status)->m_last_print_time.tv_nsec = 0;
	}

	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// These 2 function free the ring buffer and the ring buffer descriptors.
///////////////////////////////////////////////////////////////////////////////
void udig_free_ring(uint8_t* addr, uint32_t size)
{
	munmap(addr, size / 2);
	munmap(addr + size / 2, size / 2);
}

void udig_free_ring_descriptors(uint8_t* addr)
{
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);
	munmap(addr, mem_size);
}

///////////////////////////////////////////////////////////////////////////////
// Capture control helpers.
///////////////////////////////////////////////////////////////////////////////
bool acquire_and_init_ring_status_buffer(struct scap_device *dev)
{
	struct udig_ring_buffer_status* rbs = dev->m_bufstatus;
	bool res = __sync_bool_compare_and_swap(&(rbs->m_capturing_pid), 0, getpid());

	if(res)
	{
		//
		// Initialize the ring
		//
		rbs->m_stopped = 0;
		rbs->m_last_print_time.tv_sec = 0;
		rbs->m_last_print_time.tv_nsec = 0;

		//
		// Initialize the consumer
		//
		struct udig_consumer_t* consumer = &(rbs->m_consumer);

		memset(consumer, 0, sizeof(struct udig_consumer_t));
		consumer->dropping_mode = 0;
		consumer->snaplen = RW_SNAPLEN;
		consumer->sampling_ratio = 1;
		consumer->sampling_interval = 0;
		consumer->is_dropping = 0;
		consumer->do_dynamic_snaplen = false;
		consumer->need_to_insert_drop_e = 0;
		consumer->need_to_insert_drop_x = 0;
		consumer->fullcapture_port_range_start = 0;
		consumer->fullcapture_port_range_end = 0;
		consumer->statsd_port = PPM_PORT_STATSD;
	}

	return res;
}

int32_t udig_begin_capture(struct scap_engine_handle engine, char *error)
{
	struct scap_device *dev = &engine.m_handle->m_dev_set.m_devs[0];
	struct udig_ring_buffer_status* rbs = dev->m_bufstatus;

	if(rbs->m_capturing_pid != 0)
	{
		//
		// Looks like there is already a consumer, but ther variable might still
		// be set by a previous crashed consumer. To understand that, we check if
		// there is an alive process with that pid. If not, we reset the variable.
		//
		char fbuf[48];
		snprintf(fbuf, sizeof(fbuf), "/proc/%d", rbs->m_capturing_pid);
		FILE* f = fopen(fbuf, "r");
		if(f == NULL)
		{
			rbs->m_capturing_pid = 0;
		}
		else
		{
			fclose(f);
			snprintf(error, SCAP_LASTERR_SIZE, "another udig capture is already active");
			return SCAP_FAILURE;
		}
	}

	struct ppm_ring_buffer_info* rbi = dev->m_bufinfo;
	rbi->head = 0;
	rbi->tail = 0;
	rbi->n_evts = 0;
	rbi->n_drops_buffer = 0;

	if(acquire_and_init_ring_status_buffer(dev))
	{
		engine.m_handle->m_udig_capturing = true;
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(error, SCAP_LASTERR_SIZE, "cannot start the capture");
		return SCAP_FAILURE;
	}
}

void udig_start_capture(struct scap_device *dev)
{
	struct udig_ring_buffer_status* rbs = dev->m_bufstatus;
	rbs->m_stopped = 0;
}

void udig_stop_capture(struct scap_device *dev)
{
	struct udig_ring_buffer_status* rbs = dev->m_bufstatus;
	rbs->m_stopped = 1;
}

void udig_end_capture(struct scap_engine_handle engine)
{
	struct udig_ring_buffer_status* rbs = engine.m_handle->m_dev_set.m_devs[0].m_bufstatus;
	if(engine.m_handle->m_udig_capturing)
	{
		//__sync_bool_compare_and_swap(&(rbs->m_capturing_pid), getpid(), 0);
		rbs->m_capturing_pid = 0;
	}
}

int32_t udig_set_snaplen(struct scap_engine_handle engine, uint32_t snaplen)
{
	struct udig_ring_buffer_status* rbs = engine.m_handle->m_dev_set.m_devs[0].m_bufstatus;
	rbs->m_consumer.snaplen = snaplen;
	return SCAP_SUCCESS;
}

int32_t udig_stop_dropping_mode(struct scap_engine_handle engine)
{
	struct udig_consumer_t* consumer = &(engine.m_handle->m_dev_set.m_devs[0].m_bufstatus->m_consumer);
	consumer->dropping_mode = 0;
	consumer->sampling_interval = 1000000000;
	consumer->sampling_ratio = 1;

	return SCAP_SUCCESS;
}

int32_t udig_start_dropping_mode(struct scap_engine_handle engine, uint32_t sampling_ratio)
{
	struct udig_consumer_t* consumer = &(engine.m_handle->m_dev_set.m_devs[0].m_bufstatus->m_consumer);

	consumer->dropping_mode = 1;

	if(sampling_ratio != 1 &&
		sampling_ratio != 2 &&
		sampling_ratio != 4 &&
		sampling_ratio != 8 &&
		sampling_ratio != 16 &&
		sampling_ratio != 32 &&
		sampling_ratio != 64 &&
		sampling_ratio != 128) 
	{
		snprintf(engine.m_handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid sampling ratio %u\n", sampling_ratio);
		return SCAP_FAILURE;
	}

	consumer->sampling_interval = 1000000000 / sampling_ratio;
	consumer->sampling_ratio = sampling_ratio;

	return SCAP_SUCCESS;
}

void scap_close_udig(struct scap_engine_handle engine)
{
	struct udig_engine *handle = engine.m_handle;

	devset_close_device(&handle->m_dev_set.m_devs[0]);
	free(handle->m_dev_set.m_devs);
	handle->m_dev_set.m_devs = NULL;
}

static int close_engine(struct scap_engine_handle engine)
{
	udig_end_capture(engine);
	scap_close_udig(engine);

	return SCAP_SUCCESS;
}

static int32_t next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	return ringbuffer_next(&engine.m_handle->m_dev_set, pevent, pcpuid);
}

//
// Return the number of dropped events for the given handle
//
static int32_t get_stats(struct scap_engine_handle engine, OUT scap_stats* stats)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	uint32_t j;

	for(j = 0; j < devset->m_ndevs; j++)
	{
		stats->n_evts += devset->m_devs[j].m_bufinfo->n_evts;
		stats->n_drops_buffer += devset->m_devs[j].m_bufinfo->n_drops_buffer;
		stats->n_drops_pf += devset->m_devs[j].m_bufinfo->n_drops_pf;
		stats->n_drops += devset->m_devs[j].m_bufinfo->n_drops_buffer +
				  devset->m_devs[j].m_bufinfo->n_drops_pf;
		stats->n_preemptions += devset->m_devs[j].m_bufinfo->n_preemptions;
	}

	return SCAP_SUCCESS;
}

//
// Stop capturing the events
//
static int32_t stop_capture(struct scap_engine_handle engine)
{
	udig_stop_capture(&engine.m_handle->m_dev_set.m_devs[0]);

	return SCAP_SUCCESS;
}

//
// Start capturing the events
//
static int32_t start_capture(struct scap_engine_handle engine)
{
	udig_start_capture(&engine.m_handle->m_dev_set.m_devs[0]);

	return SCAP_SUCCESS;
}

static int32_t get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	return SCAP_NOT_SUPPORTED;
}

static int32_t unsupported_config(struct scap_engine_handle engine, const char* msg)
{
	strlcpy(engine.m_handle->m_lasterr, msg, SCAP_LASTERR_SIZE);
	return SCAP_FAILURE;
}

static int32_t configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	switch(setting)
	{
	case SCAP_SAMPLING_RATIO:
		if(arg2 == 0)
		{
			return udig_stop_dropping_mode(engine);
		}
		else
		{
			return udig_start_dropping_mode(engine, arg1);
		}
	case SCAP_TRACERS_CAPTURE:
		if(arg1 == 0)
		{
			return unsupported_config(engine, "Tracers cannot be disabled once enabled");
		}
		// yes, it's a no-op in udig
		return SCAP_SUCCESS;
	case SCAP_SNAPLEN:
		return udig_set_snaplen(engine, arg1);
	case SCAP_EVENTMASK:
	case SCAP_TPMASK:
	case SCAP_DYNAMIC_SNAPLEN:
	case SCAP_STATSD_PORT:
	case SCAP_FULLCAPTURE_PORT_RANGE:
		// the original code blindly tries a kmod-only ioctl
		// which can only fail. Let's return a better error code instead
		return SCAP_NOT_SUPPORTED;
	default:
	{
		char msg[256];
		snprintf(msg, sizeof(msg), "Unsupported setting %d (args %lu, %lu)", setting, arg1, arg2);
		return unsupported_config(engine, msg);
	}
	}
}

static struct udig_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct udig_engine *engine = calloc(1, sizeof(struct udig_engine));
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

static int32_t scap_udig_alloc_dev(struct scap_device* dev, char* error)
{
	//
	// Map the ring buffer.
	//
	if(udig_alloc_ring(
		&dev->m_fd,
		(uint8_t**)&dev->m_buffer,
		&dev->m_buffer_size,
		error) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	dev->m_mmap_size = 2 * dev->m_buffer_size;

	// Set close-on-exec for the fd
	if(fcntl(dev->m_fd, F_SETFD, FD_CLOEXEC) == -1) {
		return scap_errprintf(error, errno, "Can not set close-on-exec flag for fd for udig device");
	}

	//
	// Map the ppm_ring_buffer_info that contains the buffer pointers
	//
	if(udig_alloc_ring_descriptors(
		&dev->m_bufinfo_fd,
		&dev->m_bufinfo,
		&dev->m_bufstatus,
		error) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

/* `oargs` is not used here but we need to keep it to fit v-table interface. */
static int32_t init(scap_t* main_handle, scap_open_args* oargs)
{
	struct udig_engine *handle = main_handle->m_engine.m_handle;
	int rc;

	rc = devset_init(&handle->m_dev_set, 1, handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	return scap_udig_alloc_dev(&handle->m_dev_set.m_devs[0], handle->m_lasterr);
}

static uint32_t get_n_devs(struct scap_engine_handle engine)
{
	return engine.m_handle->m_dev_set.m_ndevs;
}

static uint64_t get_max_buf_used(struct scap_engine_handle engine)
{
	uint64_t i;
	uint64_t max = 0;
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;

	for(i = 0; i < devset->m_ndevs; i++)
	{
		uint64_t size = buf_size_used(&devset->m_devs[i]);
		max = size > max ? size : max;
	}

	return max;
}



const struct scap_vtable scap_udig_engine = {
	.name = UDIG_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = free_handle,
	.close = close_engine,
	.next = next,
	.start_capture = start_capture,
	.stop_capture = stop_capture,
	.configure = configure,
	.get_stats = get_stats,
	.get_n_tracepoint_hit = get_n_tracepoint_hit,
	.get_n_devs = get_n_devs,
	.get_max_buf_used = get_max_buf_used,
	.get_threadlist = scap_procfs_get_threadlist,
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = noop_getpid_global,
};
