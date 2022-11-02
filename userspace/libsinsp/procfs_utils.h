#pragma once

#include <istream>
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
 * @brief Get the path of the `name=systemd` cgroup
 * @param cgroups a stream with the contents of /proc/<pid>/cgroup
 * @return the path of the `name=systemd` cgroup
 */
std::string get_systemd_cgroup(std::istream& cgroups);

/**
 * @brief Access container data through proc
 */
class ns_helper
{
public:
	ns_helper(const std::string& host_root);
	~ns_helper();

	bool can_read_host_init_ns_mnt() const
	{
		return !m_cannot_read_host_init_ns_mnt;
	}

	const char* get_host_init_ns_mnt() const { return m_host_init_ns_mnt; }

	//! Return true if not in the host init mount namespace
	bool in_own_ns_mnt(int64_t pid) const;

	std::string get_pid_root(int64_t pid) const
	{
		return m_host_root + "/proc/" + std::to_string(pid) + "/root";
	}

private:
	const std::string& m_host_root;
	char* m_host_init_ns_mnt{nullptr};
	bool m_cannot_read_host_init_ns_mnt{false};

private:
	//
	// NOTE: at the time of writing 16 would have been enough, being
	// the format `mnt:[<unsigned>]`, but the only call to `ns_get_name`
	// I could find in the kernel was using a buffer of 50, so 50 it is.
	//
	static constexpr const std::size_t NS_MNT_SIZE{50};
};

} // namespace procfs_utils
} // namespace libsinsp
