#pragma once

#include <scap.h>

struct defs_visitor
{
    virtual ~defs_visitor() = default;

    virtual void start_events() {}
    virtual void on_event(ppm_event_code code, const char* defname, const struct ppm_event_info& info) {}
    virtual void end_events() {}

    virtual void start_sc() {}
    virtual void on_sc(ppm_sc_code code, const char* defname, const char* name) {}
    virtual void end_sc() {}
};
