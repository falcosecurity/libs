#include <libscap/scap.h>
#include <iostream>
#include <fstream>

void check_event_is_not_overwritten(scap_t* h);

void check_event_order(scap_t* h);

void check_hotplug_event(scap_t* h, std::ofstream& cpu_file);

int num_possible_cpus(void);
