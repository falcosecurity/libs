#pragma once
#include <memory>
#include <libscap/scap.h>

class scap_evt_param_reader {
	const scap_evt& m_evt;

public:
	explicit scap_evt_param_reader(const scap_evt& evt);
	size_t read_into(uint8_t param_num, void* buffer_ptr, size_t buffer_len) const;
};
