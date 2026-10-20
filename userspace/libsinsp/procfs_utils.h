#pragma once

#include <istream>
#include <cstdint>
#include <string>

namespace libsinsp {
namespace procfs_utils {

constexpr const int NO_MATCH = -1;

/**
 * @brief Parse /proc/<pid>/uid_map to find the uid that root in the userns maps to
 * @param uid_map a stream with the contents of /proc/<pid>/uid_map
 * @return the uid of the userns owner
 *
 * For unprivileged Podman containers at least, all processes are created
 * in a child user namespace which maps uids inside the container to uids
 * outside. The root user in the container is mapped to the uid that created
 * the container (in the parent user namespace)
 */
int get_userns_root_uid(std::istream& uid_map);

/**
 * @brief Parse /proc/self/cgroup to find the cgroup v2 memory.current file of the process
 * @param cgroup a stream with the contents of /proc/self/cgroup
 * @return the path of memory.current under /sys/fs/cgroup, or an empty string if there is no
 * usable cgroup v2 entry
 */
std::string get_cgroup_v2_memory_current_path(std::istream& cgroup);

/**
 * @brief Access container data through proc
 */
class ns_helper {
public:
	ns_helper(const std::string& host_root);

	bool can_read_host_init_ns_mnt() const { return !m_cannot_read_host_init_ns_mnt; }

	//! Return true if not in the host init mount namespace
	bool in_own_ns_mnt(int64_t pid) const;

	std::string get_pid_root(int64_t pid) const {
		return m_host_root + "/proc/" + std::to_string(pid) + "/root";
	}

private:
	const std::string& m_host_root;
	bool m_cannot_read_host_init_ns_mnt{false};
	int64_t m_host_init_root_inode{-1};
};

}  // namespace procfs_utils
}  // namespace libsinsp
