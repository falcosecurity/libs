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

#pragma once

#include <libsinsp/sinsp.h>
#include <libsinsp/dumper.h>

#include <memory>

class SINSP_PUBLIC sinsp_cycledumper
{

    typedef std::function<void()> callback;

public:
    sinsp_cycledumper(sinsp* inspector, const std::string& base_filename,
                    const int& rollover_mb, const int& duration_seconds,
                    const int& file_limit, const unsigned long& event_limit,
                    const bool& compress);
    ~sinsp_cycledumper();

    /*!
    \brief Dumper the event to the scap file.

    \param evt Pointer to an event.
    */
    void dump(sinsp_evt* evt);

    /*!
    \brief Close the dumper.

    \note This has to be called once the capture is ended.
    */
    void close();

    /*!
    \brief Set open and close file callbacks
    */
    void set_callbacks(std::vector<callback> open_cbs, std::vector<callback> close_cbs);

    void operator() (callback cb) { cb(); }

private:
    sinsp* m_inspector;
    std::unique_ptr<sinsp_dumper> m_dumper; //!< Underlying sinsp_dumper used.

    std::string m_base_filename; //!< The base name of the scap file.
    int m_rollover_mb; //!< Max scap file size in MB.
    int m_duration_seconds; //!< Max duration for each capture in seconds.
    int m_file_limit; //!< Max number of scap file generated.
    unsigned long m_event_limit; //!< Max number of events for each catpure.
    time_t m_last_time; //!< Last time of a capture.
    int m_file_count_total; //!< Total number of files written.
    int m_file_index; //!< Current file index.
    bool m_has_started; //!< Indicates if the cycledumper has started for the first time.
    unsigned long m_event_count; //!< Number of events of the current scap file.
    std::string *m_past_names; //!< Ring buffer to maintain the file names for scap rotation.
    std::string m_limit_format; //!< Format string for adding left padding zeros in scap filename.
    std::string m_current_filename; //!< Current file filename.
    bool m_compress; //!< Indicates if the scap file has to be compressed with zlib.
    std::string m_last_reason; //!< Last reason for a new file.
    std::vector<callback> m_open_file_callbacks;
    std::vector<callback> m_close_file_callbacks;

    /*!
    \brief Check if a new file is needed.

    \param evt Pointer to an event.

    \note to determine if a new file is needed it considers the fize size
    at the current time. The reason for the return code is written to
    m_last_reason.
    */
    bool is_new_file_needed(sinsp_evt* evt);

    /*!
    \brief Setups the new current filename.

    \note In \ref get_current_filename() will contain the new capture file
    name that will be used.
    */
    void next_file();

    /*!
    \brief Cycles the file pointer to a new capture file
    */
    void autodump_next_file();

    /*!
    \brief Stops an event dump that was started with \ref autodump_start().

    @throws a sinsp_exception containing the error string is thrown in case
    of failure.
    */
    void autodump_stop();

    /*!
    \brief Start writing the captured events to file.

    \param dump_filename the destination trace file.

    @throws a sinsp_exception containing the error string is thrown in case
    of failure.
    */
    void autodump_start(const std::string& dump_filename);
};
