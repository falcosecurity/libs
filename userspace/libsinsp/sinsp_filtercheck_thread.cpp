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

#include <libsinsp/sinsp_filtercheck_thread.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
} while(0)

#define RETURN_EXTRACT_PTR(x) do {  \
        *len = sizeof(*(x));        \
        return (uint8_t*) (x);      \
} while(0)

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_thread_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exe", "First Argument", "The first command line argument argv[0] (truncated after 4096 bytes) which is usually the executable name but it could be also a custom string, it depends on what the user specifies. This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/cmdline."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pexe", "Parent First Argument", "The proc.exe (first command line argument argv[0]) of the parent process."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.aexe", "Ancestor First Argument", "The proc.exe (first command line argument argv[0]) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aexe[1] retrieves the proc.exe of the parent process, proc.aexe[2] retrieves the proc.exe of the grandparent process, and so on. The current process's proc.exe line can be obtained using proc.aexe[0]. When used without any arguments, proc.aexe is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aexe endswith java` to match any process ancestor whose proc.exe ends with the term `java`."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exepath", "Process Executable Path", "The full executable path of the process (it could be truncated after 1024 bytes if read from '/proc'). This field is collected directly from the kernel or, as a fallback, extracted resolving the path of /proc/PID/exe, so symlinks are resolved. If you are using eBPF drivers this path could be truncated due to verifier complexity limits. (legacy eBPF kernel version < 5.2) truncated after 24 path components. (legacy eBPF kernel version >= 5.2) truncated after 48 path components. (modern eBPF kernel) truncated after 96 path components."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pexepath", "Parent Process Executable Path", "The proc.exepath (full executable path) of the parent process."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.aexepath", "Ancestor Executable Path", "The proc.exepath (full executable path) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aexepath[1] retrieves the proc.exepath of the parent process, proc.aexepath[2] retrieves the proc.exepath of the grandparent process, and so on. The current process's proc.exepath line can be obtained using proc.aexepath[0]. When used without any arguments, proc.aexepath is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aexepath endswith java` to match any process ancestor whose path ends with the term `java`."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.name", "Name", "The process name (truncated after 16 characters) generating the event (task->comm). Truncation is determined by kernel settings and not by Falco. This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/status. The name of the process and the name of the executable file on disk (if applicable) can be different if a process is given a custom name which is often the case for example for java applications."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pname", "Parent Name", "The proc.name truncated after 16 characters) of the process generating the event."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.aname", "Ancestor Name", "The proc.name (truncated after 16 characters) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aname[1] retrieves the proc.name of the parent process, proc.aname[2] retrieves the proc.name of the grandparent process, and so on. The current process's proc.name line can be obtained using proc.aname[0]. When used without any arguments, proc.aname is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aname=bash` to match any process ancestor whose name is `bash`."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.args", "Arguments", "The arguments passed on the command line when starting the process generating the event excluding argv[0] (truncated after 4096 bytes). This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/cmdline."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cmdline", "Command Line", "The concatenation of `proc.name + proc.args` (truncated after 4096 bytes) when starting the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pcmdline", "Parent Command Line", "The proc.cmdline (full command line (proc.name + proc.args)) of the parent of the process generating the event."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.acmdline", "Ancestor Command Line", "The full command line (proc.name + proc.args) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.acmdline[1] retrieves the full command line of the parent process, proc.acmdline[2] retrieves the proc.cmdline of the grandparent process, and so on. The current process's full command line can be obtained using proc.acmdline[0]. When used without any arguments, proc.acmdline is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.acmdline contains base64` to match any process ancestor whose command line contains the term base64."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.cmdnargs", "Number of Command Line args", "The number of command line args (proc.args)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.cmdlenargs", "Total Count of Characters in Command Line args", "The total count of characters / length of the command line args (proc.args) combined excluding whitespaces between args."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exeline", "Executable Command Line", "The full command line, with exe as first argument (proc.exe + proc.args) when starting the process generating the event."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.env", "Environment", "The environment variables of the process generating the event as concatenated string 'ENV_NAME=value ENV_NAME1=value1'. Can also be used to extract the value of a known env variable, e.g. proc.env[ENV_NAME]."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.aenv", "Ancestor Environment", "[EXPERIMENTAL] This field can be used in three flavors: (1) as a filter checking all parents, e.g. 'proc.aenv contains xyz', which is similar to the familiar 'proc.aname contains xyz' approach, (2) checking the `proc.env` of a specified level of the parent, e.g. 'proc.aenv[2]', which is similar to the familiar 'proc.aname[2]' approach, or (3) checking the first matched value of a known ENV_NAME in the parent lineage, such as 'proc.aenv[ENV_NAME]' (across a max of 20 ancestor levels). This field may be deprecated or undergo breaking changes in future releases. Please use it with caution."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cwd", "Current Working Directory", "The current working directory of the event."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.loginshellid", "Login Shell ID", "The pid of the oldest shell among the ancestors of the current process, if there is one. This field can be used to separate different user sessions, and is useful in conjunction with chisels like spy_user."},
	{PT_UINT32, EPF_NONE, PF_ID, "proc.tty", "Process TTY", "The controlling terminal of the process. 0 for processes without a terminal."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.pid", "Process ID", "The id of the process generating the event."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.ppid", "Parent Process ID", "The pid of the parent of the process generating the event."},
	{PT_INT64, EPF_ARG_ALLOWED, PF_ID, "proc.apid", "Ancestor Process ID", "The pid for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.apid[1] retrieves the pid of the parent process, proc.apid[2] retrieves the pid of the grandparent process, and so on. The current process's pid can be obtained using proc.apid[0]. When used without any arguments, proc.apid is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.apid=1337` to match any process ancestor whose pid is equal to 1337."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.vpid", "Virtual Process ID", "The id of the process generating the event as seen from its current PID namespace."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.pvpid", "Parent Virtual Process ID", "The id of the parent process generating the event as seen from its current PID namespace."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.sid", "Process Session ID", "The session id of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.sname", "Process Session Name", "The name of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.sid.exe", "Process Session First Argument", "The first command line argument argv[0] (usually the executable name or a custom one) of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.sid.exepath", "Process Session Executable Path", "The full executable path of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.vpgid", "Process Virtual Group ID", "The process group id of the process generating the event, as seen from its current PID namespace."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.vpgid.name", "Process Group Name", "The name of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.vpgid.exe", "Process Group First Argument", "The first command line argument argv[0] (usually the executable name or a custom one) of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.vpgid.exepath", "Process Group Executable Path", "The full executable path of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.duration", "Process Duration", "Number of nanoseconds since the process started."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.ppid.duration", "Parent Process Duration", "Number of nanoseconds since the parent process started."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.pid.ts", "Process start ts", "Start of process as epoch timestamp in nanoseconds."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.ppid.ts", "Parent Process start ts", "Start of parent process as epoch timestamp in nanoseconds."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_exe_writable", "Process Executable Is Writable", "'true' if this process' executable file is writable by the same user that spawned the process."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_exe_upper_layer", "Process Executable Is In Upper Layer", "'true' if this process' executable file is in upper layer in overlayfs. This field value can only be trusted if the underlying kernel version is greater or equal than 3.18.0, since overlayfs was introduced at that time."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_exe_from_memfd", "Process Executable Is Stored In Memfd", "'true' if the executable file of the current process is an anonymous file created using memfd_create() and is being executed by referencing its file descriptor (fd). This type of file exists only in memory and not on disk. Relevant to detect malicious in-memory code injection. Requires kernel version greater or equal to 3.17.0."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_sid_leader", "Process Is Process Session Leader", "'true' if this process is the leader of the process session, proc.sid == proc.vpid. For host processes vpid reflects pid."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_vpgid_leader", "Process Is Virtual Process Group Leader", "'true' if this process is the leader of the virtual process group, proc.vpgid == proc.vpid. For host processes vpgid and vpid reflect pgid and pid. Can help to distinguish if the process was 'directly' executed for instance in a tty (similar to bash history logging, `is_vpgid_leader` would be 'true') or executed as descendent process in the same process group which for example is the case when subprocesses are spawned from a script (`is_vpgid_leader` would be 'false')."},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.exe_ino", "Inode number of executable file on disk", "The inode number of the executable file on disk. Can be correlated with fd.ino."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "proc.exe_ino.ctime", "Last status change time (ctime) of executable file", "Last status change time of executable file (inode->ctime) as epoch timestamp in nanoseconds. Time is changed by writing or by setting inode information e.g. owner, group, link count, mode etc."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "proc.exe_ino.mtime", "Last modification time (mtime) of executable file", "Last modification time of executable file (inode->mtime) as epoch timestamp in nanoseconds. Time is changed by file modifications, e.g. by mknod, truncate, utime, write of more than zero bytes etc. For tracking changes in owner, group, link count or mode, use proc.exe_ino.ctime instead."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "proc.exe_ino.ctime_duration_proc_start", "Number of nanoseconds between ctime exe file and proc clone ts", "Number of nanoseconds between modifying status of executable image and spawning a new process using the changed executable image."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "proc.exe_ino.ctime_duration_pidns_start", "Number of nanoseconds between pidns start ts and ctime exe file", "Number of nanoseconds between PID namespace start ts and ctime exe file if PID namespace start predates ctime."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.pidns_init_start_ts", "Start ts of pid namespace", "Start of PID namespace (container or non container pid namespace) as epoch timestamp in nanoseconds."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "thread.cap_permitted", "Permitted capabilities", "The permitted capabilities set"},
	{PT_CHARBUF, EPF_NONE, PF_NA, "thread.cap_inheritable", "Inheritable capabilities", "The inheritable capabilities set"},
	{PT_CHARBUF, EPF_NONE, PF_NA, "thread.cap_effective", "Effective capabilities", "The effective capabilities set"},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_healthcheck", "Process Is Container Healthcheck", "'true' if this process is running as a part of the container's health check."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_liveness_probe", "Process Is Container Liveness", "'true' if this process is running as a part of the container's liveness probe."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_readiness_probe", "Process Is Container Readiness", "'true' if this process is running as a part of the container's readiness probe."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.fdopencount", "FD Count", "Number of open FDs for the process"},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.fdlimit", "FD Limit", "Maximum number of FDs the process can open."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "proc.fdusage", "FD Usage", "The ratio between open FDs and maximum available FDs for the process."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmsize", "VM Size", "Total virtual memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmrss", "VM RSS", "Resident non-swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmswap", "VM Swap", "Swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfmajor", "Major Page Faults", "Number of major page faults since thread start."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfminor", "Minor Page Faults", "Number of minor page faults since thread start."},
	{PT_INT64, EPF_NONE, PF_ID, "thread.tid", "Thread ID", "The id of the thread generating the event."},
	{PT_BOOL, EPF_NONE, PF_NA, "thread.ismain", "Main Thread", "'true' if the thread generating the event is the main one in the process."},
	{PT_INT64, EPF_NONE, PF_ID, "thread.vtid", "Virtual Thread ID", "The id of the thread generating the event as seen from its current PID namespace."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "thread.nametid", "Thread Name + ID", "This field chains the process name and tid of a thread and can be used as a specific identifier of a thread for a specific execve."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.exectime", "Scheduled Thread CPU Time", "CPU time spent by the last scheduled thread, in nanoseconds. Exported by switch events only."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.totexectime", "Current Thread CPU Time", "Total CPU time, in nanoseconds since the beginning of the capture, for the current thread. Exported by switch events only."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "thread.cgroups", "Thread Cgroups", "All cgroups the thread belongs to, aggregated into a single string."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "thread.cgroup", "Thread Cgroup", "The cgroup the thread belongs to, for a specific subsystem. e.g. thread.cgroup.cpuacct."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.nthreads", "Threads", "The number of alive threads that the process generating the event currently has, including the leader thread. Please note that the leader thread may not be here, in that case 'proc.nthreads' and 'proc.nchilds' are equal"},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.nchilds", "Children", "The number of alive not leader threads that the process generating the event currently has. This excludes the leader thread."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu", "Thread CPU", "The CPU consumed by the thread in the last second."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu.user", "Thread User CPU", "The user CPU consumed by the thread in the last second."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu.system", "Thread System CPU", "The system CPU consumed by the thread in the last second."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.vmsize", "Thread VM Size (kb)", "For the process main thread, this is the total virtual memory for the process (as kb). For the other threads, this field is zero."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.vmrss", "Thread VM RSS (kb)", "For the process main thread, this is the resident non-swapped memory for the process (as kb). For the other threads, this field is zero."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "thread.vmsize.b", "Thread VM Size (b)", "For the process main thread, this is the total virtual memory for the process (in bytes). For the other threads, this field is zero."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "thread.vmrss.b", "Thread VM RSS (b)", "For the process main thread, this is the resident non-swapped memory for the process (in bytes). For the other threads, this field is zero."},
};

sinsp_filter_check_thread::sinsp_filter_check_thread()
{
	m_info.m_name = "process";
	m_info.m_desc = "Additional information about the process and thread executing the syscall event.";
	m_info.m_fields = sinsp_filter_check_thread_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_thread_fields) / sizeof(sinsp_filter_check_thread_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;

	m_u64val = 0;
	m_cursec_ts = 0;
}

sinsp_filter_check* sinsp_filter_check_thread::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_thread();
}

int32_t sinsp_filter_check_thread::extract_arg(std::string fldname, std::string val, OUT const ppm_param_info** parinfo)
{
	std::string::size_type parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(m_field_id == TYPE_APID ||
		m_field_id == TYPE_ANAME ||
		m_field_id == TYPE_AEXE ||
		m_field_id == TYPE_AEXEPATH ||
		m_field_id == TYPE_ACMDLINE)
	{
		if(val[fldname.size()] == '[')
		{
			parsed_len = val.find(']');
			if(parsed_len == std::string::npos)
			{
				throw sinsp_exception("the field '" + fldname + "' requires an argument but ']' is not found");
			}
			string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);
			m_argid = sinsp_numparser::parsed32(numstr);
			parsed_len++;
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
	}
	else if(m_field_id == TYPE_ENV ||
			m_field_id == TYPE_AENV	)
	{
		if(val[fldname.size()] == '[')
		{
			std::string::size_type startpos = fldname.size();
			parsed_len = val.find(']', startpos);

			if(parsed_len == std::string::npos)
			{
				throw sinsp_exception("the field '" + fldname + "' requires an argument but ']' is not found");
			}
			m_argname = val.substr(startpos + 1, parsed_len - startpos - 1);
			if(!m_argname.empty() && std::all_of(m_argname.begin(), m_argname.end(), [](unsigned char c) { return std::isdigit(c); }))
			{
				m_argid = sinsp_numparser::parsed32(m_argname);
				m_argname.clear();
			}
			parsed_len++;
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
	}
	else if(m_field_id == TYPE_CGROUP)
	{
		if(val[fldname.size()] == '.')
		{
			std::string::size_type endpos;
			for(endpos = fldname.size() + 1; endpos < val.length(); ++endpos)
			{
				if(!isalpha(val[endpos])
					&& val[endpos] != '_')
				{
					break;
				}
			}

			parsed_len = endpos;
			m_argname = val.substr(fldname.size() + 1, endpos - fldname.size() - 1);
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
	}

	return (int32_t)parsed_len;
}

int32_t sinsp_filter_check_thread::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);

	if(STR_MATCH("arg"))
	{
		//
		// 'arg' is handled in a custom way
		//
		throw sinsp_exception("filter error: proc.arg filter not implemented yet");
	}
	else if(STR_MATCH("proc.apid"))
	{
		m_field_id = TYPE_APID;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.apid", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.apid")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(STR_MATCH("proc.aname"))
	{
		m_field_id = TYPE_ANAME;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.aname", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.aname")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(STR_MATCH("proc.aexepath"))
	{
		m_field_id = TYPE_AEXEPATH;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.aexepath", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.aexepath")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	/* note: because of str similarity of proc.aexe to proc.aexepath, this needs to be placed after proc.aexepath */
	else if(STR_MATCH("proc.aexe"))
	{
		m_field_id = TYPE_AEXE;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.aexe", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.aexe")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(STR_MATCH("proc.acmdline"))
	{
		m_field_id = TYPE_ACMDLINE;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.acmdline", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.acmdline")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(STR_MATCH("proc.env"))
	{
		m_field_id = TYPE_ENV;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.env", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.env")
			{
				m_argname.clear();
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(STR_MATCH("proc.aenv"))
	{
		m_field_id = TYPE_AENV;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.aenv", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.aenv")
			{
				m_argname.clear();
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(STR_MATCH("thread.totexectime"))
	{
		//
		// Allocate thread storage for the value
		//
		if(alloc_state)
		{
			auto acc = m_inspector->m_thread_manager->dynamic_fields()->add_field<uint64_t>("_tmp_sinsp_filter_thread_totexectime");
			m_thread_dyn_field_accessor.reset(new libsinsp::state::dynamic_struct::field_accessor<uint64_t>(acc.new_accessor<uint64_t>()));
		}

		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
	else if(STR_MATCH("thread.cgroup") &&
			!STR_MATCH("thread.cgroups"))
	{
		m_field_id = TYPE_CGROUP;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("thread.cgroup", val, NULL);
	}
	else if(STR_MATCH("thread.cpu"))
	{
		if(alloc_state)
		{
			auto acc = m_inspector->m_thread_manager->dynamic_fields()->add_field<uint64_t>("_tmp_sinsp_filter_thread_cpu");
			m_thread_dyn_field_accessor.reset(new libsinsp::state::dynamic_struct::field_accessor<uint64_t>(acc.new_accessor<uint64_t>()));
		}

		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
}

uint64_t sinsp_filter_check_thread::extract_exectime(sinsp_evt *evt)
{
	uint64_t res = 0;

	if(m_last_proc_switch_times.size() == 0)
	{
		//
		// Initialize the vector of CPU times
		//
		const scap_machine_info* minfo = m_inspector->get_machine_info();
		ASSERT(minfo->num_cpus != 0);

		if (minfo == NULL || minfo->num_cpus == 0) {
			return res;
		}

		for(uint32_t j = 0; j < minfo->num_cpus; j++)
		{
			m_last_proc_switch_times.push_back(0);
		}
	}

	uint32_t cpuid = evt->get_cpuid();
	uint64_t ts = evt->get_ts();
	uint64_t lasttime = m_last_proc_switch_times[cpuid];

	if(lasttime != 0)
	{
		res = ts - lasttime;
	}

	ASSERT(cpuid < m_last_proc_switch_times.size());

	m_last_proc_switch_times[cpuid] = ts;

	return res;
}

uint8_t* sinsp_filter_check_thread::extract_thread_cpu(sinsp_evt *evt, OUT uint32_t* len, sinsp_threadinfo* tinfo, bool extract_user, bool extract_system)
{
	uint16_t etype = evt->get_type();

	if(etype == PPME_PROCINFO_E)
	{
		uint64_t user = 0;
		uint64_t system = 0;
		uint64_t tcpu;

		if(extract_user)
		{
			user = evt->get_param(0)->as<uint64_t>();
		}

		if(extract_system)
		{
			system = evt->get_param(1)->as<uint64_t>();
		}

		tcpu = user + system;

		uint64_t last_t_tot_cpu = 0;
		tinfo->get_dynamic_field(*m_thread_dyn_field_accessor.get(), last_t_tot_cpu);
		if(last_t_tot_cpu != 0)
		{
			uint64_t deltaval = tcpu - last_t_tot_cpu;
			m_dval = (double)deltaval;// / (ONE_SECOND_IN_NS / 100);
			if(m_dval > 100)
			{
				m_dval = 100;
			}
		}
		else
		{
			m_dval = 0;
		}

		tinfo->set_dynamic_field(*m_thread_dyn_field_accessor.get(), tcpu);

		RETURN_EXTRACT_VAR(m_dval);
	}

	return NULL;
}

// Some syscall sources, such as the gVisor integration, cannot match events to host PIDs and TIDs.
// The event will retain the PID field which is consistent with the rest of sinsp logic, but it won't represent
// a real PID and so it should not be displayed to the user.
inline bool should_extract_xid(int64_t xid)
{
	return xid >= -1 && xid <= UINT32_MAX;
}

uint8_t* sinsp_filter_check_thread::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL &&
		m_field_id != TYPE_TID &&
		m_field_id != TYPE_EXECTIME &&
		m_field_id != TYPE_TOTEXECTIME)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_TID:
		m_s64val = evt->get_tid();
		if (!should_extract_xid(m_s64val))
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_PID:
		if (!should_extract_xid(tinfo->m_pid))
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_pid);
	case TYPE_SID:
		RETURN_EXTRACT_VAR(tinfo->m_sid);
	case TYPE_VPGID:
		RETURN_EXTRACT_VAR(tinfo->m_vpgid);
	case TYPE_SNAME:
		{
			int64_t sid = tinfo->m_sid;

			if(!tinfo->is_in_pid_namespace())
			{
				// Relying on the convention that a session id is the process id of the session leader.
				// `threadinfo` lookup only applies when the process is running on the host and not in a pid
				// namespace. However, if the process is running in a pid namespace, we instead traverse the process
				// lineage until we find a match.
				sinsp_threadinfo* sinfo = m_inspector->get_thread_ref(sid, false, true).get();
				if(sinfo != NULL)
				{
					m_tstr = sinfo->get_comm();
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			// This can occur when the session leader process has exited or if the process
			// is running in a pid namespace and we only have the virtual session id, as
			// seen from its pid namespace.
			// Find the highest ancestor process that has the same session id and
			// declare it to be the session leader.
			sinsp_threadinfo* session_leader = tinfo;

			sinsp_threadinfo::visitor_func_t visitor = [sid, &session_leader](sinsp_threadinfo* pt)
			{
				if(pt->m_sid != sid)
				{
					return false;
				}
				session_leader = pt;
				return true;
			};

			tinfo->traverse_parent_state(visitor);

			// session_leader has been updated to the highest process that has the same session id.
			// session_leader's comm is considered the session leader.
			m_tstr = session_leader->get_comm();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_SID_EXE:
		{
			int64_t sid = tinfo->m_sid;

			if(!tinfo->is_in_pid_namespace())
			{
				// Relying on the convention that a session id is the process id of the session leader.
				// `threadinfo` lookup only applies when the process is running on the host and not in a pid
				// namespace. However, if the process is running in a pid namespace, we instead traverse the process
				// lineage until we find a match.
				sinsp_threadinfo* sinfo = m_inspector->get_thread_ref(sid, false, true).get();
				if(sinfo != NULL)
				{
					m_tstr = sinfo->get_exe();
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			// This can occur when the session leader process has exited or if the process
			// is running in a pid namespace and we only have the virtual session id, as
			// seen from its pid namespace.
			// Find the highest ancestor process that has the same session id and
			// declare it to be the session leader.
			sinsp_threadinfo* session_leader = tinfo;

			sinsp_threadinfo::visitor_func_t visitor = [sid, &session_leader](sinsp_threadinfo* pt)
			{
				if(pt->m_sid != sid)
				{
					return false;
				}
				session_leader = pt;
				return true;
			};

			tinfo->traverse_parent_state(visitor);

			// session_leader has been updated to the highest process that has the same session id.
			// session_leader's exe is considered the session leader.
			m_tstr = session_leader->get_exe();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_SID_EXEPATH:
		{
			int64_t sid = tinfo->m_sid;

			if(!tinfo->is_in_pid_namespace())
			{
				// Relying on the convention that a session id is the process id of the session leader.
				// `threadinfo` lookup only applies when the process is running on the host and not in a pid
				// namespace. However, if the process is running in a pid namespace, we instead traverse the process
				// lineage until we find a match.
				sinsp_threadinfo* sinfo = m_inspector->get_thread_ref(sid, false, true).get();
				if(sinfo != NULL)
				{
					m_tstr = sinfo->get_exepath();
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			// This can occur when the session leader process has exited or if the process
			// is running in a pid namespace and we only have the virtual session id, as
			// seen from its pid namespace.
			// Find the highest ancestor process that has the same session id and
			// declare it to be the session leader.
			sinsp_threadinfo* session_leader = tinfo;

			sinsp_threadinfo::visitor_func_t visitor = [sid, &session_leader](sinsp_threadinfo* pt)
			{
				if(pt->m_sid != sid)
				{
					return false;
				}
				session_leader = pt;
				return true;
			};

			tinfo->traverse_parent_state(visitor);

			// session_leader has been updated to the highest process that has the same session id.
			// session_leader's exepath is considered the session leader.
			m_tstr = session_leader->get_exepath();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_VPGID_NAME:
		{
			int64_t vpgid = tinfo->m_vpgid;

			if(!tinfo->is_in_pid_namespace())
			{
				// Relying on the convention that a process group id is the process id of the process group leader.
				// `threadinfo` lookup only applies when the process is running on the host and not in a pid
				// namespace. However, if the process is running in a pid namespace, we instead traverse the process
				// lineage until we find a match.
				sinsp_threadinfo* vpgidinfo = m_inspector->get_thread_ref(vpgid, false, true).get();
				if(vpgidinfo != NULL)
				{
					m_tstr = vpgidinfo->get_comm();
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}
			// This can occur when the process group leader process has exited or if the process
			// is running in a pid namespace and we only have the virtual process group id, as
			// seen from its pid namespace.
			// Find the highest ancestor process that has the same process group id and
			// declare it to be the process group leader.
			sinsp_threadinfo* group_leader = tinfo;

			sinsp_threadinfo::visitor_func_t visitor = [vpgid, &group_leader](sinsp_threadinfo* pt)
			{
				if(pt->m_vpgid != vpgid)
				{
					return false;
				}
				group_leader = pt;
				return true;
			};

			tinfo->traverse_parent_state(visitor);

			// group_leader has been updated to the highest process that has the same process group id.
			// group_leader's comm is considered the process group leader.
			m_tstr = group_leader->get_comm();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_VPGID_EXE:
		{
			int64_t vpgid = tinfo->m_vpgid;

			if(!tinfo->is_in_pid_namespace())
			{
				// Relying on the convention that a process group id is the process id of the process group leader.
				// `threadinfo` lookup only applies when the process is running on the host and not in a pid
				// namespace. However, if the process is running in a pid namespace, we instead traverse the process
				// lineage until we find a match.
				sinsp_threadinfo* vpgidinfo = m_inspector->get_thread_ref(vpgid, false, true).get();
				if(vpgidinfo != NULL)
				{
					m_tstr = vpgidinfo->get_exe();
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}
			// This can occur when the process group leader process has exited or if the process
			// is running in a pid namespace and we only have the virtual process group id, as
			// seen from its pid namespace.
			// Find the highest ancestor process that has the same process group id and
			// declare it to be the process group leader.
			sinsp_threadinfo* group_leader = tinfo;

			sinsp_threadinfo::visitor_func_t visitor = [vpgid, &group_leader](sinsp_threadinfo* pt)
			{
				if(pt->m_vpgid != vpgid)
				{
					return false;
				}
				group_leader = pt;
				return true;
			};

			tinfo->traverse_parent_state(visitor);

			// group_leader has been updated to the highest process that has the same process group id.
			// group_leader's exe is considered the process group leader.
			m_tstr = group_leader->get_exe();
			RETURN_EXTRACT_STRING(m_tstr);

		}
	case TYPE_VPGID_EXEPATH:
		{
			int64_t vpgid = tinfo->m_vpgid;

			if(!tinfo->is_in_pid_namespace())
			{
				// Relying on the convention that a process group id is the process id of the process group leader.
				// `threadinfo` lookup only applies when the process is running on the host and not in a pid
				// namespace. However, if the process is running in a pid namespace, we instead traverse the process
				// lineage until we find a match.
				sinsp_threadinfo* vpgidinfo = m_inspector->get_thread_ref(vpgid, false, true).get();
				if(vpgidinfo != NULL)
				{
					m_tstr = vpgidinfo->get_exepath();
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			// This can occur when the process group leader process has exited or if the process
			// is running in a pid namespace and we only have the virtual process group id, as
			// seen from its pid namespace.
			// Find the highest ancestor process that has the same process group id and
			// declare it to be the process group leader.
			sinsp_threadinfo* group_leader = tinfo;

			sinsp_threadinfo::visitor_func_t visitor = [vpgid, &group_leader](sinsp_threadinfo* pt)
			{
				if(pt->m_vpgid != vpgid)
				{
					return false;
				}
				group_leader = pt;
				return true;
			};

			tinfo->traverse_parent_state(visitor);

			// group_leader has been updated to the highest process that has the same process group id.
			// group_leader's exepath is considered the process group leader.
			m_tstr = group_leader->get_exepath();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_TTY:
		RETURN_EXTRACT_VAR(tinfo->m_tty);
	case TYPE_NAME:
		m_tstr = tinfo->get_comm();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_EXE:
		m_tstr = tinfo->get_exe();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_EXEPATH:
		m_tstr = tinfo->get_exepath();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_ARGS:
		{
			m_tstr.clear();

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_args[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_ENV:
		{
			m_tstr.clear();

			// proc.env[ENV_NAME] use case: returns matched env variable value
			if(!m_argname.empty())
			{
				m_tstr = tinfo->get_env(m_argname);
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				m_tstr = tinfo->concatenate_all_env();
				RETURN_EXTRACT_STRING(m_tstr);
			}
		}
	case TYPE_AENV:
		{
			m_tstr.clear();

			// in case of proc.aenv without [ENV_NAME] return proc.env; same applies for proc.aenv[0]
			if(m_argname.empty() && m_argid < 1)
			{
				m_tstr = tinfo->concatenate_all_env();
				RETURN_EXTRACT_STRING(m_tstr);
			}

			// get current tinfo / init for subsequent parent lineage traversal
			sinsp_threadinfo* mt = NULL;
			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();
				if(mt == NULL)
				{
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			if(!m_argname.empty()) // extract a specific ENV_NAME value
			{
				// start parent lineage traversal
				for(int32_t j = 0; j < 20; j++) // up to 20 levels, but realistically we will exit way before given the mt nullptr check
				{
					mt = mt->get_parent_thread();

					if(mt == NULL)
					{
						break;
					}

					m_tstr = mt->get_env(m_argname);
					if(!m_tstr.empty())
					{
						break;
					}
				}
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else if(m_argid > 0)
			{
				// start parent lineage traversal
				for(int32_t j = 0; j < m_argid; j++)
				{
					mt = mt->get_parent_thread();

					if(mt == NULL)
					{
						return NULL;
					}
				}

				// parent tinfo specified found; extract env
				m_tstr = mt->concatenate_all_env();
				RETURN_EXTRACT_STRING(m_tstr);
			}
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_CMDLINE:
		{
			sinsp_threadinfo::populate_cmdline(m_tstr, tinfo);
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_EXELINE:
		{
			m_tstr = tinfo->get_exe() + " ";

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_args[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_CWD:
		m_tstr = tinfo->get_cwd();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_NTHREADS:
		{
			m_u64val = tinfo->get_num_threads();
			RETURN_EXTRACT_VAR(m_u64val);
		}
		break;
	case TYPE_NCHILDS:
		{
			m_u64val = tinfo->get_num_not_leader_threads();
			RETURN_EXTRACT_VAR(m_u64val);
		}
		break;
	case TYPE_ISMAINTHREAD:
		m_tbool = (uint32_t)tinfo->is_main_thread();
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_EXECTIME:
		{
			m_u64val = 0;
			uint16_t etype = evt->get_type();

			if(etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
			{
				m_u64val = extract_exectime(evt);
			}

			RETURN_EXTRACT_VAR(m_u64val);
		}
	case TYPE_TOTEXECTIME:
		{
			m_u64val = 0;
			uint16_t etype = evt->get_type();

			if(etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
			{
				m_u64val = extract_exectime(evt);
			}

			sinsp_threadinfo* tinfo = evt->get_thread_info(false);

			if(tinfo != NULL)
			{
				uint64_t ptot = 0;
				tinfo->get_dynamic_field(*m_thread_dyn_field_accessor.get(), ptot);
				m_u64val += ptot;
				tinfo->set_dynamic_field(*m_thread_dyn_field_accessor.get(), m_u64val);
				RETURN_EXTRACT_VAR(m_u64val);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PPID:
		if(tinfo->is_main_thread())
		{
			if (!should_extract_xid(tinfo->m_ptid))
			{
				return NULL;
			}
			RETURN_EXTRACT_VAR(tinfo->m_ptid);
		}
		else
		{
			sinsp_threadinfo* mt = tinfo->get_main_thread();

			if(mt != NULL)
			{
				if (!should_extract_xid(mt->m_ptid))
				{
					return NULL;
				}
				RETURN_EXTRACT_VAR(mt->m_ptid);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PNAME:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				m_tstr = ptinfo->get_comm();
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PCMDLINE:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				sinsp_threadinfo::populate_cmdline(m_tstr, ptinfo);
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
		case TYPE_ACMDLINE:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}
			sinsp_threadinfo::populate_cmdline(m_tstr, mt);
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_APID:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			//
			// Search for a specific ancestors
			//
			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			if (!should_extract_xid(mt->m_pid))
			{
				return NULL;
			}
			RETURN_EXTRACT_VAR(mt->m_pid);
		}
	case TYPE_ANAME:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			m_tstr = mt->get_comm();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_PEXE:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				m_tstr = ptinfo->get_exe();
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_AEXE:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			m_tstr = mt->get_exe();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_PEXEPATH:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				m_tstr = ptinfo->get_exepath();
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_AEXEPATH:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			m_tstr = mt->get_exepath();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_LOGINSHELLID:
		{
			sinsp_threadinfo* mt = NULL;
			int64_t* res = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			sinsp_threadinfo::visitor_func_t check_thread_for_shell = [&res] (sinsp_threadinfo *pt)
			{
				size_t len = pt->m_comm.size();

				if(len >= 2 && pt->m_comm[len - 2] == 's' && pt->m_comm[len - 1] == 'h')
				{
					res = &pt->m_pid;
				}

				return true;
			};

			// First call the visitor on the main thread.
			check_thread_for_shell(mt);

			// Then check all its parents to see if they are shells
			mt->traverse_parent_state(check_thread_for_shell);

			RETURN_EXTRACT_PTR(res);
		}
	case TYPE_DURATION:
		if(tinfo->m_clone_ts != 0)
		{
			m_s64val = evt->get_ts() - tinfo->m_clone_ts;
			ASSERT(m_s64val > 0);
			RETURN_EXTRACT_VAR(m_s64val);
		}
		else
		{
			return NULL;
		}
	case TYPE_PPID_DURATION:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				if(ptinfo->m_clone_ts != 0)
				{
					m_s64val = evt->get_ts() - ptinfo->m_clone_ts;
					ASSERT(m_s64val > 0);
					RETURN_EXTRACT_VAR(m_s64val);
				}
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_FDOPENCOUNT:
		m_u64val = tinfo->get_fd_opencount();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_FDLIMIT:
		m_s64val = tinfo->get_fd_limit();
		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_FDUSAGE:
		m_dval = tinfo->get_fd_usage_pct_d();
		RETURN_EXTRACT_VAR(m_dval);
	case TYPE_VMSIZE:
		m_u64val = tinfo->m_vmsize_kb;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_VMRSS:
		m_u64val = tinfo->m_vmrss_kb;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_VMSWAP:
		m_u64val = tinfo->m_vmswap_kb;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMSIZE:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmsize_kb;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMRSS:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmrss_kb;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMSIZE_B:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmsize_kb * 1024;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMRSS_B:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmrss_kb * 1024;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PFMAJOR:
		m_u64val = tinfo->m_pfmajor;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PFMINOR:
		m_u64val = tinfo->m_pfminor;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_CGROUPS:
		{
			m_tstr.clear();
			auto cgroups = tinfo->cgroups();

			uint32_t j;
			uint32_t nargs = (uint32_t)cgroups.size();

			if(nargs == 0)
			{
				return NULL;
			}

			for(j = 0; j < nargs; j++)
			{
				m_tstr += cgroups[j].first;
				m_tstr += "=";
				m_tstr += cgroups[j].second;
				if(j < nargs - 1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_CGROUP:
		if(tinfo->get_cgroup(m_argname, m_tstr))
		{
			RETURN_EXTRACT_STRING(m_tstr);
		}
		return NULL;
	case TYPE_VTID:
		if(tinfo->m_vtid == -1)
		{
			return NULL;
		}

		m_u64val = tinfo->m_vtid;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_VPID:
		if(tinfo->m_vpid == -1)
		{
			return NULL;
		}

		m_u64val = tinfo->m_vpid;
		RETURN_EXTRACT_VAR(m_u64val);
/*
	case TYPE_PROC_CPU:
		{
			uint16_t etype = evt->get_type();

			if(etype == PPME_PROCINFO_E)
			{
				double thval;
				uint64_t tcpu;

				sinsp_evt_param* parinfo = evt->get_param(0);
				tcpu = *(uint64_t*)parinfo->m_val;

				parinfo = evt->get_param(1);
				tcpu += *(uint64_t*)parinfo->m_val;

				if(tinfo->m_last_t_tot_cpu != 0)
				{
					uint64_t deltaval = tcpu - tinfo->m_last_t_tot_cpu;
					thval = (double)deltaval;// / (ONE_SECOND_IN_NS / 100);
					if(thval > 100)
					{
						thval = 100;
					}
				}
				else
				{
					thval = 0;
				}

				tinfo->m_last_t_tot_cpu = tcpu;

				uint64_t ets = evt->get_ts();
				sinsp_threadinfo* mt = tinfo->get_main_thread();

				if(ets != mt->m_last_mt_cpu_ts)
				{
					mt->m_last_mt_tot_cpu = 0;
					mt->m_last_mt_cpu_ts = ets;
				}

				mt->m_last_mt_tot_cpu += thval;
				m_dval = mt->m_last_mt_tot_cpu;

				RETURN_EXTRACT_VAR(m_dval);
			}

			return NULL;
		}
*/
	case TYPE_THREAD_CPU:
		{
			return extract_thread_cpu(evt, len, tinfo, true, true);
		}
	case TYPE_THREAD_CPU_USER:
		{
			return extract_thread_cpu(evt, len, tinfo, true, false);
		}
	case TYPE_THREAD_CPU_SYSTEM:
		{
			return extract_thread_cpu(evt, len, tinfo, false, true);
		}
	case TYPE_NAMETID:
		m_tstr = tinfo->get_comm() + to_string(evt->get_tid());
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_IS_CONTAINER_HEALTHCHECK:
		m_tbool = (tinfo->m_category == sinsp_threadinfo::CAT_HEALTHCHECK);
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_CONTAINER_LIVENESS_PROBE:
		m_tbool = (tinfo->m_category == sinsp_threadinfo::CAT_LIVENESS_PROBE);
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_CONTAINER_READINESS_PROBE:
		m_tbool = (tinfo->m_category == sinsp_threadinfo::CAT_READINESS_PROBE);
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_EXE_WRITABLE:
		m_tbool = tinfo->m_exe_writable;
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_EXE_UPPER_LAYER:
		m_tbool = tinfo->m_exe_upper_layer;
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_EXE_FROM_MEMFD:
		m_tbool = tinfo->m_exe_from_memfd;
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_SID_LEADER:
		m_tbool = tinfo->m_sid == tinfo->m_vpid;
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_VPGID_LEADER:
		m_tbool = tinfo->m_vpgid == tinfo->m_vpid;
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_CAP_PERMITTED:
		m_tstr = sinsp_utils::caps_to_string(tinfo->m_cap_permitted);
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CAP_INHERITABLE:
		m_tstr = sinsp_utils::caps_to_string(tinfo->m_cap_inheritable);
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CAP_EFFECTIVE:
		m_tstr = sinsp_utils::caps_to_string(tinfo->m_cap_effective);
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CMDNARGS:
		{
			m_u64val = (uint32_t)tinfo->m_args.size();
			RETURN_EXTRACT_VAR(m_u64val);
		}
	case TYPE_CMDLENARGS:
		{
			m_u64val = 0;
			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

			for(j = 0; j < nargs; j++)
			{
				m_u64val += tinfo->m_args[j].length();

			}
			RETURN_EXTRACT_VAR(m_u64val);
		}
	case TYPE_PVPID:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				RETURN_EXTRACT_VAR(ptinfo->m_vpid);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_EXE_INO:
		// Inode 0 is used as a NULL value to indicate that there is no inode.
		if(tinfo->m_exe_ino == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_exe_ino);
	case TYPE_EXE_INO_CTIME:
		if(tinfo->m_exe_ino_ctime == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_exe_ino_ctime);
	case TYPE_EXE_INO_MTIME:
		if(tinfo->m_exe_ino_mtime == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_exe_ino_mtime);
	case TYPE_EXE_INO_CTIME_DURATION_CLONE_TS:
		if(tinfo->m_exe_ino_ctime_duration_clone_ts == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_exe_ino_ctime_duration_clone_ts);
	case TYPE_EXE_INO_CTIME_DURATION_PIDNS_START:
		if(tinfo->m_exe_ino_ctime_duration_pidns_start == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_exe_ino_ctime_duration_pidns_start);
	case TYPE_PIDNS_INIT_START_TS:
		if(tinfo->m_pidns_init_start_ts == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_pidns_init_start_ts);
	case TYPE_PID_CLONE_TS:
		if(tinfo->m_clone_ts == 0)
		{
			return NULL;
		}
		RETURN_EXTRACT_VAR(tinfo->m_clone_ts);
	case TYPE_PPID_CLONE_TS:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				RETURN_EXTRACT_VAR(ptinfo->m_clone_ts);
			}
			else
			{
				return NULL;
			}
		}
	default:
		ASSERT(false);
		return NULL;
	}
}

bool sinsp_filter_check_thread::compare_full_apid(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;

		res = flt_compare(m_cmpop,
				  PT_PID,
				  &pt->m_pid);

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare_full_aname(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;

		res = flt_compare(m_cmpop,
				  PT_CHARBUF,
				  (void*)pt->m_comm.c_str());

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare_full_aexe(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;

		res = flt_compare(m_cmpop,
				  PT_CHARBUF,
				  (void*)pt->m_exe.c_str());

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare_full_aexepath(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;

		res = flt_compare(m_cmpop,
				  PT_CHARBUF,
				  (void*)pt->m_exepath.c_str());

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare_full_acmdline(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;
		std::string cmdline;
		sinsp_threadinfo::populate_cmdline(cmdline, pt);

		res = flt_compare(m_cmpop,
				  PT_CHARBUF,
				  (void*)cmdline.c_str());

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare_full_aenv(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		std::string full_env = pt->concatenate_all_env();
		bool res = flt_compare(m_cmpop,
				  PT_CHARBUF,
				  (void*)full_env.c_str());

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare(sinsp_evt *evt)
{
	if(m_field_id == TYPE_APID)
	{
		if(m_argid == -1)
		{
			return compare_full_apid(evt);
		}
	}
	else if(m_field_id == TYPE_ANAME)
	{
		if(m_argid == -1)
		{
			return compare_full_aname(evt);
		}
	}
	else if(m_field_id == TYPE_AEXE)
	{
		if(m_argid == -1)
		{
			return compare_full_aexe(evt);
		}
	}
	else if(m_field_id == TYPE_AEXEPATH)
	{
		if(m_argid == -1)
		{
			return compare_full_aexepath(evt);
		}
	}
	else if(m_field_id == TYPE_ACMDLINE)
	{
		if(m_argid == -1)
		{
			return compare_full_acmdline(evt);
		}
	}
	else if(m_field_id == TYPE_AENV)
	{
		if(m_argname.empty())
		{
			return compare_full_aenv(evt);
		}
	}

	return sinsp_filter_check::compare(evt);
}

int32_t sinsp_filter_check_thread::get_argid() const
{
	return m_argid;
}
