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

#include <filesystem>
#include <libsinsp/sinsp_filtercheck_fspath.h>
#include <libsinsp/sinsp_filtercheck_event.h>
#include <libsinsp/sinsp_filtercheck_fd.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static const filtercheck_field_info sinsp_filter_check_fspath_fields[] =
	{
		{PT_CHARBUF, EPF_NONE, PF_NA, "fs.path.name", "Path for Filesystem-related operation", "For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed."},
		{PT_CHARBUF, EPF_NONE, PF_NA, "fs.path.nameraw", "Raw path for Filesystem-related operation", "For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always the path provided to the syscall and may not be fully resolved."},
		{PT_CHARBUF, EPF_NONE, PF_NA, "fs.path.source", "Source path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed."},
		{PT_CHARBUF, EPF_NONE, PF_NA, "fs.path.sourceraw", "Source path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always the path provided to the syscall and may not be fully resolved."},
		{PT_CHARBUF, EPF_NONE, PF_NA, "fs.path.target", "Target path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed."},
		{PT_CHARBUF, EPF_NONE, PF_NA, "fs.path.targetraw", "Target path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always the path provided to the syscall and may not be fully resolved."},
};

sinsp_filter_check_fspath::sinsp_filter_check_fspath()
	// These will either be populated when calling
	// create_fspath_checks or copied from another filtercheck
	// when calling set_fspath_checks().
	: m_success_checks(new filtercheck_map_t()),
	  m_path_checks(new filtercheck_map_t()),
	  m_source_checks(new filtercheck_map_t()),
	  m_target_checks(new filtercheck_map_t())
{
	m_info.m_name = "fs.path";
	m_info.m_desc = "Every syscall that has a filesystem path in its arguments has these fields set with information related to the path arguments. This differs from the fd.* fields as it includes syscalls like unlink, rename, etc. that act directly on filesystem paths as compared to opened file descriptors.";
	m_info.m_fields = sinsp_filter_check_fspath_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_fspath_fields) / sizeof(sinsp_filter_check_fspath_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;
};

std::shared_ptr<sinsp_filter_check> sinsp_filter_check_fspath::create_event_check(const char *name,
										  cmpop cop,
										  const char *value)
{
	std::shared_ptr<sinsp_filter_check> chk(new sinsp_filter_check_event());

	chk->m_inspector = m_inspector;
	chk->m_cmpop = cop;
	chk->m_boolop = BO_NONE;
	chk->parse_field_name(name, true, true);

	if(value)
	{
		chk->add_filter_value(value, strlen(value), 0);
	}

	return chk;
}

std::shared_ptr<sinsp_filter_check> sinsp_filter_check_fspath::create_fd_check(const char *name)
{
	std::shared_ptr<sinsp_filter_check> chk(new sinsp_filter_check_fd());

	chk->m_inspector = m_inspector;
	chk->m_cmpop = CO_NONE;
	chk->m_boolop = BO_NONE;
	chk->parse_field_name(name, true, true);

	return chk;
}

void sinsp_filter_check_fspath::create_fspath_checks()
{
	std::shared_ptr<sinsp_filter_check> evt_arg_path = create_event_check("evt.rawarg.path");
	std::shared_ptr<sinsp_filter_check> evt_arg_pathname = create_event_check("evt.rawarg.pathname");
	std::shared_ptr<sinsp_filter_check> evt_arg_res_eq_0 = create_event_check("evt.rawarg.res", CO_EQ, "0");
	std::shared_ptr<sinsp_filter_check> evt_arg_name = create_event_check("evt.rawarg.name");
	std::shared_ptr<sinsp_filter_check> evt_fd_name = create_fd_check("fd.name");
	std::shared_ptr<sinsp_filter_check> evt_arg_fd_ne_neg1 = create_event_check("evt.rawarg.fd", CO_NE, "-1");
	std::shared_ptr<sinsp_filter_check> evt_arg_oldpath = create_event_check("evt.rawarg.oldpath");
	std::shared_ptr<sinsp_filter_check> evt_arg_newpath = create_event_check("evt.rawarg.newpath");
	std::shared_ptr<sinsp_filter_check> evt_arg_linkpath = create_event_check("evt.rawarg.linkpath");
	std::shared_ptr<sinsp_filter_check> evt_arg_target = create_event_check("evt.rawarg.target");
	std::shared_ptr<sinsp_filter_check> evt_arg_filename = create_event_check("evt.rawarg.filename");
	std::shared_ptr<sinsp_filter_check> evt_arg_special = create_event_check("evt.rawarg.special");
	std::shared_ptr<sinsp_filter_check> evt_arg_dev = create_event_check("evt.rawarg.dev");
	std::shared_ptr<sinsp_filter_check> evt_arg_dir = create_event_check("evt.rawarg.dir");

	m_success_checks->emplace(PPME_SYSCALL_MKDIR_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_MKDIR_2_X, evt_arg_path);
	m_success_checks->emplace(PPME_SYSCALL_MKDIR_2_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_MKDIRAT_X, evt_arg_path);
	m_success_checks->emplace(PPME_SYSCALL_MKDIRAT_X, evt_arg_res_eq_0);

	m_success_checks->emplace(PPME_SYSCALL_RMDIR_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_RMDIR_2_X, evt_arg_path);
	m_success_checks->emplace(PPME_SYSCALL_RMDIR_2_X, evt_arg_res_eq_0);

	m_success_checks->emplace(PPME_SYSCALL_UNLINK_X, evt_arg_res_eq_0);

	m_success_checks->emplace(PPME_SYSCALL_UNLINKAT_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_UNLINK_2_X, evt_arg_path);
	m_success_checks->emplace(PPME_SYSCALL_UNLINK_2_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_UNLINKAT_2_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_UNLINKAT_2_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_OPEN_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_OPEN_X, evt_arg_fd_ne_neg1);

	m_success_checks->emplace(PPME_SYSCALL_OPENAT_X, evt_arg_fd_ne_neg1);

	m_path_checks->emplace(PPME_SYSCALL_OPENAT_2_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_OPENAT_2_X, evt_arg_fd_ne_neg1);

	m_path_checks->emplace(PPME_SYSCALL_OPENAT2_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_OPENAT2_X, evt_arg_fd_ne_neg1);

	m_path_checks->emplace(PPME_SYSCALL_FCHMODAT_X, evt_arg_filename);
	m_success_checks->emplace(PPME_SYSCALL_FCHMODAT_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_CHMOD_X, evt_arg_filename);
	m_success_checks->emplace(PPME_SYSCALL_CHMOD_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_FCHMOD_X, evt_fd_name);
	m_success_checks->emplace(PPME_SYSCALL_FCHMOD_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_CHOWN_X, evt_arg_path);
	m_success_checks->emplace(PPME_SYSCALL_CHOWN_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_LCHOWN_X, evt_arg_path);
	m_success_checks->emplace(PPME_SYSCALL_LCHOWN_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_FCHOWN_X, evt_fd_name);
	m_success_checks->emplace(PPME_SYSCALL_FCHOWN_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_FCHOWNAT_X, evt_arg_pathname);
	m_success_checks->emplace(PPME_SYSCALL_FCHOWNAT_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_QUOTACTL_X, evt_arg_special);
	m_success_checks->emplace(PPME_SYSCALL_QUOTACTL_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_RENAME_X, evt_arg_oldpath);
	m_target_checks->emplace(PPME_SYSCALL_RENAME_X, evt_arg_newpath);
	m_success_checks->emplace(PPME_SYSCALL_RENAME_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_RENAMEAT_X, evt_arg_oldpath);
	m_target_checks->emplace(PPME_SYSCALL_RENAMEAT_X, evt_arg_newpath);
	m_success_checks->emplace(PPME_SYSCALL_RENAMEAT_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_RENAMEAT2_X, evt_arg_oldpath);
	m_target_checks->emplace(PPME_SYSCALL_RENAMEAT2_X, evt_arg_newpath);
	m_success_checks->emplace(PPME_SYSCALL_RENAMEAT2_X, evt_arg_res_eq_0);

	m_success_checks->emplace(PPME_SYSCALL_LINK_X, evt_arg_res_eq_0);

	m_success_checks->emplace(PPME_SYSCALL_LINKAT_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_LINK_2_X, evt_arg_newpath);
	m_target_checks->emplace(PPME_SYSCALL_LINK_2_X, evt_arg_oldpath);
	m_success_checks->emplace(PPME_SYSCALL_LINK_2_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_LINKAT_2_X, evt_arg_newpath);
	m_target_checks->emplace(PPME_SYSCALL_LINKAT_2_X, evt_arg_oldpath);
	m_success_checks->emplace(PPME_SYSCALL_LINKAT_2_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_SYMLINK_X, evt_arg_linkpath);
	m_target_checks->emplace(PPME_SYSCALL_SYMLINK_X, evt_arg_target);
	m_success_checks->emplace(PPME_SYSCALL_SYMLINK_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_SYMLINKAT_X, evt_arg_linkpath);
	m_target_checks->emplace(PPME_SYSCALL_SYMLINKAT_X, evt_arg_target);
	m_success_checks->emplace(PPME_SYSCALL_SYMLINKAT_X, evt_arg_res_eq_0);

	m_source_checks->emplace(PPME_SYSCALL_MOUNT_X, evt_arg_dev);
	m_target_checks->emplace(PPME_SYSCALL_MOUNT_X, evt_arg_dir);
	m_success_checks->emplace(PPME_SYSCALL_MOUNT_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_UMOUNT_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_UMOUNT_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_UMOUNT_1_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_UMOUNT_1_X, evt_arg_res_eq_0);

	m_path_checks->emplace(PPME_SYSCALL_UMOUNT2_X, evt_arg_name);
	m_success_checks->emplace(PPME_SYSCALL_UMOUNT2_X, evt_arg_res_eq_0);
}

void sinsp_filter_check_fspath::set_fspath_checks(std::shared_ptr<filtercheck_map_t> success_checks,
						  std::shared_ptr<filtercheck_map_t> path_checks,
						  std::shared_ptr<filtercheck_map_t> source_checks,
						  std::shared_ptr<filtercheck_map_t> target_checks)
{
	m_success_checks = success_checks;
	m_path_checks = path_checks;
	m_source_checks = source_checks;
	m_target_checks = target_checks;
}

sinsp_filter_check* sinsp_filter_check_fspath::allocate_new()
{
	// If not yet populated, do so now. The maps will be empty
	// *only* for the initial filtercheck created in
	// filter_check_list.
	if(m_path_checks->empty())
	{
		create_fspath_checks();
	}

	sinsp_filter_check_fspath* ret = new sinsp_filter_check_fspath();

	ret->set_fspath_checks(m_success_checks, m_path_checks, m_source_checks, m_target_checks);

	return ret;
}

uint8_t* sinsp_filter_check_fspath::extract(sinsp_evt* evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	ASSERT(evt);

	// First check the success conditions.
	auto it = m_success_checks->find(evt->get_type());
	if(it == m_success_checks->end() || !it->second->compare(evt))
	{
		return NULL;
	}

	std::optional<std::reference_wrapper<const std::string>> enter_param;
	std::vector<extract_value_t> extract_values;

	switch(m_field_id)
	{
	case TYPE_NAME:
	case TYPE_NAMERAW:

		// For some event types we need to get the values from the enter event instead.
		switch(evt->get_type())
		{
		case PPME_SYSCALL_MKDIR_X:
		case PPME_SYSCALL_RMDIR_X:
		case PPME_SYSCALL_UNLINK_X:
			enter_param = evt->get_enter_evt_param("path");
			if(!enter_param.has_value())
			{
				return NULL;
			}
			m_tstr = enter_param.value();
			break;
		case PPME_SYSCALL_UNLINKAT_X:
		case PPME_SYSCALL_OPENAT_X:
			enter_param = evt->get_enter_evt_param("name");
			if(!enter_param.has_value())
			{
				return NULL;
			}
			m_tstr = enter_param.value();
			break;
		default:
			if (!extract_fspath(evt, extract_values, m_path_checks))
			{
				return NULL;
			}
			m_tstr.assign((const char*) extract_values[0].ptr, strnlen((const char*) extract_values[0].ptr, extract_values[0].len));
		};

		break;
	case TYPE_SOURCE:
	case TYPE_SOURCERAW:
		// For some event types we need to get the values from the enter event instead.
		switch(evt->get_type())
		{
		case PPME_SYSCALL_LINK_X:
		case PPME_SYSCALL_LINKAT_X:
			enter_param = evt->get_enter_evt_param("newpath");
			if(!enter_param.has_value())
			{
				return NULL;
			}
			m_tstr = enter_param.value();
			break;
		default:
			if(!extract_fspath(evt, extract_values, m_source_checks))
			{
				return NULL;
			}
			m_tstr.assign((const char*) extract_values[0].ptr, strnlen((const char*) extract_values[0].ptr, extract_values[0].len));
		};
		break;
	case TYPE_TARGET:
	case TYPE_TARGETRAW:

		// For some event types we need to get the values from the enter event instead.
		switch(evt->get_type())
		{
		case PPME_SYSCALL_LINK_X:
		case PPME_SYSCALL_LINKAT_X:
			enter_param = evt->get_enter_evt_param("oldpath");
			if(!enter_param.has_value())
			{
				return NULL;
			}
			m_tstr = enter_param.value();
			break;
		default:
			if (!extract_fspath(evt, extract_values, m_target_checks))
			{
				return NULL;
			}
			m_tstr.assign((const char*) extract_values[0].ptr, strnlen((const char*) extract_values[0].ptr, extract_values[0].len));
		};
		break;
	default:
		return NULL;
	}

	// For the non-raw fields, if the path is not absolute,
	// prepend the cwd of the threadinfo to the path.
	if((m_field_id == TYPE_NAME ||
	    m_field_id == TYPE_SOURCE ||
	    m_field_id == TYPE_TARGET))
	{
		sinsp_threadinfo* tinfo = evt->get_thread_info();

		if(tinfo == NULL)
		{
			return NULL;
		}

		if(!std::filesystem::path(m_tstr).is_absolute())
		{
			m_tstr = sinsp_utils::concatenate_paths(tinfo->get_cwd(), m_tstr);
		} else
		{
			// concatenate_paths takes care of resolving the path
			m_tstr = sinsp_utils::concatenate_paths("", m_tstr);
		}
	}

	RETURN_EXTRACT_STRING(m_tstr);
}

bool sinsp_filter_check_fspath::extract_fspath(sinsp_evt* evt,
					       OUT std::vector<extract_value_t>& values,
					       std::shared_ptr<filtercheck_map_t> checks)
{
	sinsp_evt* extract_evt = evt;

	auto it = checks->find(extract_evt->get_type());
	if(it == checks->end())
	{
		return false;
	}

	if(!it->second->extract(extract_evt, values, true) ||
	   values.size() != 1)
	{
		return false;
	}

	return true;
}
