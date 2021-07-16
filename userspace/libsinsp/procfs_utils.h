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

}
}
