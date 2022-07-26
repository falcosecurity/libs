#pragma once

#include <stdlib.h>

//
// Structs used for testing
//

struct ppm_evt_hdr;
struct scap_threadinfo;
struct scap_fdinfo;

struct scap_test_fdinfo_data {
  const struct scap_fdinfo *fdinfos;
  size_t fdinfo_count;
};

typedef struct scap_test_thread_data scap_test_thread_data;

struct scap_test_input_data {
  struct ppm_evt_hdr** events;
  size_t event_count;

  struct scap_threadinfo *threads;
  size_t thread_count;

  struct scap_test_fdinfo_data *fdinfo_data;
};

typedef struct scap_test_input_data scap_test_input_data;
