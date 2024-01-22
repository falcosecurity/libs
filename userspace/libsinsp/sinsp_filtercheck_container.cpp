// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/sinsp_filtercheck_container.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
} while(0)

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static const filtercheck_field_info sinsp_filter_check_container_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.id", "Container ID", "The truncated container ID (first 12 characters), e.g. 3ad7b26ded6d is extracted from the Linux cgroups by Falco within the kernel. Consequently, this field is reliably available and serves as the lookup key for Falco's synchronous or asynchronous requests against the container runtime socket to retrieve all other 'container.*' information. One important aspect to be aware of is that if the process occurs on the host, meaning not in the container PID namespace, this field is set to a string called 'host'. In Kubernetes, pod sandbox container processes can exist where `container.id` matches `k8s.pod.sandbox_id`, lacking other 'container.*' details."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.full_id", "Container ID", "The full container ID, e.g. 3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e. In contrast to `container.id`, we enrich this field as part of the container engine enrichment. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.name", "Container Name", "The container name. In instances of userspace container engine lookup delays, this field may not be available yet. One important aspect to be aware of is that if the process occurs on the host, meaning not in the container PID namespace, this field is set to a string called 'host'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image", "Image Name", "The container image name (e.g. falcosecurity/falco:latest for docker). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.id", "Image ID", "The container image id (e.g. 6f7e2741b66b). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.type", "Type", "The container type, e.g. docker, cri-o, containerd etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "container.privileged", "Privileged", "'true' for containers running as privileged, 'false' otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.mounts", "Mounts", "A space-separated list of mount information. Each item in the list has the format <source>:<dest>:<mode>:<rdrw>:<propagation>. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount", "Mount", "Information about a single mount, specified by number (e.g. container.mount[0]) or mount source (container.mount[/usr/local]). The pathname can be a glob (container.mount[/usr/local/*]), in which case the first matching mount will be returned. The information has the format <source>:<dest>:<mode>:<rdrw>:<propagation>. If there is no mount with the specified index or matching the provided source, returns the string \"none\" instead of a NULL value. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.source", "Mount Source", "The mount source, specified by number (e.g. container.mount.source[0]) or mount destination (container.mount.source[/host/lib/modules]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.dest", "Mount Destination", "The mount destination, specified by number (e.g. container.mount.dest[0]) or mount source (container.mount.dest[/lib/modules]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.mode", "Mount Mode", "The mount mode, specified by number (e.g. container.mount.mode[0]) or mount source (container.mount.mode[/usr/local]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.rdwr", "Mount Read/Write", "The mount rdwr value, specified by number (e.g. container.mount.rdwr[0]) or mount source (container.mount.rdwr[/usr/local]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.propagation", "Mount Propagation", "The mount propagation value, specified by number (e.g. container.mount.propagation[0]) or mount source (container.mount.propagation[/usr/local]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.repository", "Repository", "The container image repository (e.g. falcosecurity/falco). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.tag", "Image Tag", "The container image tag (e.g. stable, latest). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.digest", "Registry Digest", "The container image registry digest (e.g. sha256:d977378f890d445c15e51795296e4e5062f109ce6da83e0a355fc4ad8699d27). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.healthcheck", "Health Check", "The container's health check. Will be the null value (\"N/A\") if no healthcheck configured, \"NONE\" if configured but explicitly not created, and the healthcheck command line otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.liveness_probe", "Liveness", "The container's liveness probe. Will be the null value (\"N/A\") if no liveness probe configured, the liveness probe command line otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.readiness_probe", "Readiness", "The container's readiness probe. Will be the null value (\"N/A\") if no readiness probe configured, the readiness probe command line otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_UINT64, EPF_NONE, PF_DEC, "container.start_ts", "Container start", "Container start as epoch timestamp in nanoseconds based on proc.pidns_init_start_ts and extracted in the kernel and not from the container runtime socket / container engine."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "container.duration", "Number of nanoseconds since container.start_ts", "Number of nanoseconds since container.start_ts."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.ip", "Container ip address", "The container's / pod's primary ip address as retrieved from the container engine. Only ipv4 addresses are tracked. Consider container.cni.json (CRI use case) for logging ip addresses for each network interface. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.cni.json", "Container's / pod's CNI result json", "The container's / pod's CNI result field from the respective pod status info. It contains ip addresses for each network interface exposed as unparsed escaped JSON string. Supported for CRI container engine (containerd, cri-o runtimes), optimized for containerd (some non-critical JSON keys removed). Useful for tracking ips (ipv4 and ipv6, dual-stack support) for each network interface (multi-interface support). In instances of userspace container engine lookup delays, this field may not be available yet."},
};

sinsp_filter_check_container::sinsp_filter_check_container()
{
	m_info.m_name = "container";
	m_info.m_desc = "Container information. If the event is not happening inside a container, both id and name will be set to 'host'.";
	m_info.m_fields = sinsp_filter_check_container_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_container_fields) / sizeof(sinsp_filter_check_container_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;
}

sinsp_filter_check* sinsp_filter_check_container::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_container();
}

int32_t sinsp_filter_check_container::extract_arg(const string &val, size_t basepos)
{
	size_t start = val.find_first_of('[', basepos);
	if(start == string::npos)
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	size_t end = val.find_first_of(']', start);
	if(end == string::npos)
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	string numstr = val.substr(start + 1, end-start-1);
	try
	{
		m_argid = sinsp_numparser::parsed32(numstr);
	}
	catch (const sinsp_exception& e)
	{
		if(strstr(e.what(), "is not a valid number") == NULL)
		{
			throw;
		}

		m_argid = -1;
		m_argstr = numstr;
	}

	return end+1;
}

const std::string &sinsp_filter_check_container::get_argstr() const
{
	return m_argstr;
}

int32_t sinsp_filter_check_container::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);
	int32_t res = 0;

	size_t basepos = sizeof("container.mount");

	// container.mount. fields allow for indexing by number or source/dest mount path.
	if(val.find("container.mount.") == 0)
	{
		// Note--basepos includes the trailing null, which is
		// equivalent to the trailing '.' here.
		if(val.find("source", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_SOURCE;
		}
		else if(val.find("dest", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_DEST;
		}
		else if(val.find("mode", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_MODE;
		}
		else if(val.find("rdwr", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_RDWR;
		}
		else if(val.find("propagation", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_PROPAGATION;
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg(val, basepos);
	}
	else if (val.find("container.mount") == 0 &&
		 val[basepos-1] != 's')
	{
		m_field_id = TYPE_CONTAINER_MOUNT;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg(val, basepos-1);
	}
	else
	{
		res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}

	return res;
}


uint8_t* sinsp_filter_check_container::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return NULL;
	}

	sinsp_container_info::ptr_t container_info = NULL;
	bool is_host = tinfo->m_container_id.empty() && !tinfo->is_in_pid_namespace();

	if(!tinfo->m_container_id.empty())
	{
		container_info = m_inspector->m_container_manager.get_container(tinfo->m_container_id);	
	}

	switch(m_field_id)
	{
	case TYPE_CONTAINER_ID:
		if(is_host)
		{
			m_tstr = "host";
		}
		else
		{
			m_tstr = tinfo->m_container_id;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_FULL_CONTAINER_ID:
		if(is_host)
		{
			m_tstr = "host";
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			if(container_info->m_full_id.empty())
			{
				return NULL;
			}

			m_tstr = container_info->m_full_id;
		}
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_NAME:
		if(is_host)
		{
			m_tstr = "host";
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			if(container_info->m_name.empty())
			{
				return NULL;
			}

			m_tstr = container_info->m_name;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_IMAGE:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			if(container_info->m_image.empty())
			{
				return NULL;
			}

			m_tstr = container_info->m_image;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_IMAGE_ID:
	case TYPE_CONTAINER_IMAGE_REPOSITORY:
	case TYPE_CONTAINER_IMAGE_TAG:
	case TYPE_CONTAINER_IMAGE_DIGEST:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			const string *field;
			switch(m_field_id)
			{
			case TYPE_CONTAINER_IMAGE_ID:
				field = &container_info->m_imageid;
				break;
			case TYPE_CONTAINER_IMAGE_REPOSITORY:
				field = &container_info->m_imagerepo;
				break;
			case TYPE_CONTAINER_IMAGE_TAG:
				field = &container_info->m_imagetag;
				break;
			case TYPE_CONTAINER_IMAGE_DIGEST:
				field = &container_info->m_imagedigest;
				break;
			default:
				return nullptr;
			}

			if(field->empty())
			{
				return NULL;
			}

			m_tstr = *field;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_TYPE:
		if(is_host)
		{
			m_tstr = "host";
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}
			switch(container_info->m_type)
			{
			case sinsp_container_type::CT_DOCKER:
				m_tstr = "docker";
				break;
			case sinsp_container_type::CT_LXC:
				m_tstr = "lxc";
				break;
			case sinsp_container_type::CT_LIBVIRT_LXC:
				m_tstr = "libvirt-lxc";
				break;
			case sinsp_container_type::CT_MESOS:
				m_tstr = "mesos";
				break;
			case sinsp_container_type::CT_CRI:
				m_tstr = "cri";
				break;
			case sinsp_container_type::CT_CONTAINERD:
				m_tstr = "containerd";
				break;
			case sinsp_container_type::CT_CRIO:
				m_tstr = "cri-o";
				break;
			case sinsp_container_type::CT_RKT:
				m_tstr = "rkt";
				break;
			case sinsp_container_type::CT_BPM:
				m_tstr = "bpm";
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_PRIVILEGED:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			// Only return a true/false value for
			// container types where we really know the
			// privileged status.
			if (!is_docker_compatible(container_info->m_type))
			{
				return NULL;
			}

			m_u32val = (container_info->m_privileged ? 1 : 0);
		}

		RETURN_EXTRACT_VAR(m_u32val);
		break;
	case TYPE_CONTAINER_MOUNTS:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			m_tstr = "";
			bool first = true;
			for(auto &mntinfo : container_info->m_mounts)
			{
				if(first)
				{
					first = false;
				}
				else
				{
					m_tstr += ",";
				}

				m_tstr += mntinfo.to_string();
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}

		break;
	case TYPE_CONTAINER_MOUNT:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			const sinsp_container_info::container_mount_info *mntinfo;

			if(m_argid != -1)
			{
				mntinfo = container_info->mount_by_idx(m_argid);
			}
			else
			{
				mntinfo = container_info->mount_by_source(m_argstr);
			}

			if(!mntinfo)
			{
				return NULL;
			}
			else
			{
				m_tstr = mntinfo->to_string();
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}

		break;
	case TYPE_CONTAINER_MOUNT_SOURCE:
	case TYPE_CONTAINER_MOUNT_DEST:
	case TYPE_CONTAINER_MOUNT_MODE:
	case TYPE_CONTAINER_MOUNT_RDWR:
	case TYPE_CONTAINER_MOUNT_PROPAGATION:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			const sinsp_container_info::container_mount_info *mntinfo;

			if(m_argid != -1)
			{
				mntinfo = container_info->mount_by_idx(m_argid);
			}
			else
			{
				if (m_field_id == TYPE_CONTAINER_MOUNT_SOURCE)
				{
					mntinfo = container_info->mount_by_dest(m_argstr);
				}
				else
				{
					mntinfo = container_info->mount_by_source(m_argstr);
				}
			}

			if(!mntinfo)
			{
				return NULL;
			}

			switch (m_field_id)
			{
			case TYPE_CONTAINER_MOUNT_SOURCE:
				m_tstr = mntinfo->m_source;
				break;
			case TYPE_CONTAINER_MOUNT_DEST:
				m_tstr = mntinfo->m_dest;
				break;
			case TYPE_CONTAINER_MOUNT_MODE:
				m_tstr = mntinfo->m_mode;
				break;
			case TYPE_CONTAINER_MOUNT_RDWR:
				m_tstr = (mntinfo->m_rdwr ? "true" : "false");
				break;
			case TYPE_CONTAINER_MOUNT_PROPAGATION:
				m_tstr = mntinfo->m_propagation;
				break;
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_CONTAINER_HEALTHCHECK:
	case TYPE_CONTAINER_LIVENESS_PROBE:
	case TYPE_CONTAINER_READINESS_PROBE:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}

			for(auto &probe : container_info->m_health_probes)
			{
				if((m_field_id == TYPE_CONTAINER_HEALTHCHECK &&
				    probe.m_probe_type == sinsp_container_info::container_health_probe::PT_HEALTHCHECK) ||
				   (m_field_id == TYPE_CONTAINER_LIVENESS_PROBE &&
				    probe.m_probe_type == sinsp_container_info::container_health_probe::PT_LIVENESS_PROBE) ||
				   (m_field_id == TYPE_CONTAINER_READINESS_PROBE &&
				    probe.m_probe_type == sinsp_container_info::container_health_probe::PT_READINESS_PROBE))
				{
					m_tstr = probe.m_health_probe_exe;

					for(auto &arg : probe.m_health_probe_args)
					{
						m_tstr += " ";
						m_tstr += arg;
					}

					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			// If here, then the container didn't have any
			// health probe matching the filtercheck
			// field.
			m_tstr = "NONE";
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_CONTAINER_START_TS:
		if(is_host || tinfo->m_pidns_init_start_ts == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_pidns_init_start_ts);
		break;
	case TYPE_CONTAINER_DURATION:
		if(is_host || tinfo->m_clone_ts == 0)
		{
			return NULL;
		}
		m_s64val = evt->get_ts() - tinfo->m_pidns_init_start_ts;
		ASSERT(m_s64val > 0);
		RETURN_EXTRACT_VAR(m_s64val);
		break;
	case TYPE_CONTAINER_IP_ADDR:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}
			m_u32val = htonl(container_info->m_container_ip);
			char addrbuff[100];
			inet_ntop(AF_INET, &m_u32val, addrbuff, sizeof(addrbuff));
			m_tstr = addrbuff;
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_CONTAINER_CNIRESULT:
		if(is_host)
		{
			return NULL;
		}
		else
		{
			if(!container_info)
			{
				return NULL;
			}
			RETURN_EXTRACT_STRING(container_info->m_pod_cniresult);
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
