#pragma once

#include "../event_class/event_class.h"

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <memory>
#include <string>

class file_opener
{

public:
    file_opener(const char* filename, int flags, int dirfd = AT_FDCWD);
    ~file_opener();

    void close();
    bool is_tmpfile_supported() const;
    int get_fd() const;
    int get_flags() const;
    const char* get_pathname() const;

private:
    bool m_tmpfile_supported;
    std::string m_pathname;
    int m_flags;
    int m_fd;

};
