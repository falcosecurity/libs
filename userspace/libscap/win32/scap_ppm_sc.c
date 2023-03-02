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

#include "scap.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int scap_get_modifies_state_ppm_sc(OUT uint8_t ppm_sc_array[PPM_SC_MAX])
{
	return SCAP_FAILURE;
}

int scap_get_events_from_ppm_sc(IN const uint8_t ppm_sc_array[PPM_SC_MAX], OUT uint8_t events_array[PPM_EVENT_MAX])
{
	return SCAP_FAILURE;
}

int scap_get_ppm_sc_from_events(IN const uint8_t events_array[PPM_EVENT_MAX], OUT uint8_t ppm_sc_array[PPM_SC_MAX])
{
	return SCAP_FAILURE;
}

ppm_sc_code scap_ppm_sc_from_name(const char *name)
{
	return PPM_SC_UNKNOWN;
}

ppm_sc_code scap_native_id_to_ppm_sc(int native_id)
{
	return PPM_SC_UNKNOWN;
}