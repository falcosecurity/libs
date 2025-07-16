#include <libsinsp/state/static_struct.h>

void libsinsp::state::static_table_fields::fields(
        std::vector<ss_plugin_table_fieldinfo>& out) const {
	for(const auto& info : *m_static_fields) {
		ss_plugin_table_fieldinfo i;
		i.name = info.second.name().c_str();
		i.field_type = info.second.info().type_id();
		i.read_only = info.second.readonly();
		out.push_back(i);
	}
}

libsinsp::state::accessor::ptr libsinsp::state::static_table_fields::field(
        const char* name,
        const typeinfo& type_info) {
	auto it = m_static_fields->find(name);
	if(it == m_static_fields->end()) {
		return accessor::null();
	}

	if(type_info.type_id() != it->second.info().type_id()) {
		throw sinsp_exception("incompatible data types for static field: " + std::string(name));
	}
	return it->second.new_accessor();
}

libsinsp::state::accessor::ptr libsinsp::state::static_table_fields::new_field(
        const char* name,
        const typeinfo& type_info) {
	throw sinsp_exception("cannot add static fields at runtime: " + std::string(name));
}
