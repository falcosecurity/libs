#pragma once

#include <stdlib.h>

//
// Structs used for testing
//

struct ppm_evt_hdr;

struct scap_test_input_data {
  struct ppm_evt_hdr** events;
  size_t event_count;
};

typedef struct scap_test_input_data scap_test_input_data;
