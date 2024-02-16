#include "file_opener.h"
#include <fcntl.h>

file_opener::file_opener(const char* filename, int flags, int dirfd)
{
    m_fd = syscall(__NR_openat, dirfd, filename, flags, 0);
	assert_syscall_state(SYSCALL_SUCCESS, "openat", m_fd, NOT_EQUAL, -1);
    m_tmpfile_supported = (errno == EOPNOTSUPP);
    if(flags & O_DIRECTORY && strcmp(filename, ".") == 0)
    {
        m_pathname = m_tmpfile_supported? std::string(".tmpfile") : std::string(".");
    }
    else
    {
        m_pathname = std::string(filename);
    }

    m_flags = flags;

    if(!m_tmpfile_supported && m_flags & O_TMPFILE)
    {
        m_flags ^= O_TMPFILE;
        m_flags |= O_CREAT;
    }
}

file_opener::~file_opener()
{
    close();
}

void file_opener::close()
{
    syscall(__NR_close, m_fd);
    if(m_tmpfile_supported)
    {
        unlink(m_pathname.c_str());
    }
}

const bool file_opener::is_tmpfile_supported() const
{
    return m_tmpfile_supported;
}

const int file_opener::get_fd() const
{
    return m_fd;
}

const int file_opener::get_flags() const
{
    return m_flags;
}

const char* file_opener::get_pathname() const
{
    return m_pathname.c_str();
}
