// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <libsinsp/sinsp_int.h>
#include <libsinsp/metrics_collector.h>
#include <libsinsp/plugin_manager.h>
#include <cmath>
#include <re2/re2.h>

#ifdef __linux__
#include <libsinsp/linux/resource_utilization.h>
#endif

static re2::RE2 s_libs_metrics_units_suffix_pre_prometheus_text_conversion(
        "(_kb|_bytes|_mb|_perc|_percentage|_ratio|_ns|_ts|_sec|_total)",
        re2::RE2::POSIX);
static re2::RE2 s_libs_metrics_units_memory_suffix("(_kb|_bytes)", re2::RE2::POSIX);
static re2::RE2 s_libs_metrics_units_perc_suffix("(_perc)", re2::RE2::POSIX);

// For simplicity, needs to stay in sync w/ typedef enum metrics_v2_value_unit
// https://prometheus.io/docs/practices/naming/ or
// https://prometheus.io/docs/practices/naming/#base-units.
static const char* const metrics_unit_name_mappings_prometheus[] = {
        "total",
        "ratio",
        "percentage",
        "bytes",
        "kibibytes",
        "megabytes",
        "nanoseconds",
        "seconds",
        "nanoseconds_total",
        "seconds_total",
        "timestamp_nanoseconds",
};

static_assert(sizeof(metrics_unit_name_mappings_prometheus) /
                              sizeof(metrics_unit_name_mappings_prometheus[0]) ==
                      METRIC_VALUE_UNIT_MAX,
              "metrics_unit_name_mappings_prometheus array size does not match expected size");

// For simplicity, needs to stay in sync w/ typedef enum metrics_v2_metric_type
// https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
static const char* const metrics_metric_type_name_mappings_prometheus[] = {
        "counter",
        "gauge",
};

namespace libs::metrics {

std::string metric_value_to_text(const metrics_v2& metric) {
	std::string value_text;
	switch(metric.type) {
	case METRIC_VALUE_TYPE_U32:
		value_text = std::to_string(metric.value.u32);
		break;
	case METRIC_VALUE_TYPE_S32:
		value_text = std::to_string(metric.value.s32);
		break;
	case METRIC_VALUE_TYPE_U64:
		value_text = std::to_string(metric.value.u64);
		break;
	case METRIC_VALUE_TYPE_S64:
		value_text = std::to_string(metric.value.s64);
		break;
	case METRIC_VALUE_TYPE_D:
		value_text = std::to_string(metric.value.d);
		break;
	case METRIC_VALUE_TYPE_F:
		value_text = std::to_string(metric.value.f);
		break;
	case METRIC_VALUE_TYPE_I:
		value_text = std::to_string(metric.value.i);
		break;
	default:
		ASSERT(false);
		break;
	}
	return value_text;
}

std::string prometheus_sanitize_metric_name(const std::string& name,
                                            const RE2& invalid_chars = RE2("[^a-zA-Z0-9_:]")) {
	// https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels
	std::string sanitized_name = name;
	RE2::GlobalReplace(&sanitized_name, invalid_chars, "_");
	RE2::GlobalReplace(&sanitized_name, "_+", "_");
	// Ensure it starts with a letter or underscore (if empty after sanitizing, set to "_")
	if(sanitized_name.empty() ||
	   (!std::isalpha(sanitized_name.front()) && sanitized_name.front() != '_')) {
		sanitized_name = "_" + sanitized_name;
	}
	return sanitized_name;
}

std::string prometheus_qualifier(std::string_view prometheus_namespace,
                                 std::string_view prometheus_subsystem) {
	std::string qualifier;
	if(!prometheus_namespace.empty()) {
		qualifier += std::string(prometheus_namespace) + "_";
	}
	if(!prometheus_subsystem.empty()) {
		qualifier += std::string(prometheus_subsystem) + "_";
	}
	return qualifier;
}

std::string prometheus_exposition_text(std::string_view metric_qualified_name,
                                       std::string_view metric_name,
                                       std::string_view metric_type_name,
                                       std::string_view metric_value,
                                       const std::map<std::string, std::string>& const_labels) {
	std::string fqn = prometheus_sanitize_metric_name(std::string(metric_qualified_name));
	std::string prometheus_text = "# HELP " + fqn + " https://falco.org/docs/metrics/\n";
	prometheus_text += "# TYPE " + fqn + " " + std::string(metric_type_name) + "\n";
	prometheus_text += fqn;
	if(!const_labels.empty()) {
		static const RE2 label_invalid_chars("[^a-zA-Z0-9_]");
		prometheus_text += "{";
		bool first_label = true;
		for(const auto& [key, value] : const_labels) {
			if(key.empty()) {
				continue;
			}
			if(!first_label) {
				prometheus_text += ",";
			} else {
				first_label = false;
			}
			prometheus_text += prometheus_sanitize_metric_name(key, label_invalid_chars) + "=\"" +
			                   value + "\"";
		}
		prometheus_text += "} ";  // the white space at the end is important!
	} else {
		prometheus_text += " ";  // the white space at the end is important!
	}
	prometheus_text += std::string(metric_value);
	prometheus_text += "\n";
	return prometheus_text;
}

std::string metrics_converter::convert_metric_to_text(const metrics_v2& metric) const {
	return std::string(metric.name) + " " + metric_value_to_text(metric) + "\n";
}

void metrics_converter::convert_metric_to_unit_convention(metrics_v2& /*metric*/) const {
	// Default does nothing
}

void output_rule_metrics_converter::convert_metric_to_unit_convention(metrics_v2& metric) const {
	if((metric.unit == METRIC_VALUE_UNIT_MEMORY_BYTES ||
	    metric.unit == METRIC_VALUE_UNIT_MEMORY_KIBIBYTES) &&
	   (metric.type == METRIC_VALUE_TYPE_U32 || metric.type == METRIC_VALUE_TYPE_U64)) {
		if(metric.type == METRIC_VALUE_TYPE_U32) {
			metric.value.d = libs::metrics::convert_memory(metric.unit,
			                                               METRIC_VALUE_UNIT_MEMORY_MEGABYTES,
			                                               metric.value.u32);
		} else if(metric.type == METRIC_VALUE_TYPE_U64) {
			metric.value.d = libs::metrics::convert_memory(metric.unit,
			                                               METRIC_VALUE_UNIT_MEMORY_MEGABYTES,
			                                               metric.value.u64);
		}
		std::string metric_name_str(metric.name);
		RE2::GlobalReplace(&metric_name_str, s_libs_metrics_units_memory_suffix, "_mb");
		strlcpy(metric.name, metric_name_str.c_str(), METRIC_NAME_MAX);
		metric.type = METRIC_VALUE_TYPE_D;
		metric.unit = METRIC_VALUE_UNIT_MEMORY_MEGABYTES;
	}
}

std::string prometheus_metrics_converter::convert_metric_to_text_prometheus(
        const metrics_v2& metric,
        std::string_view prometheus_namespace,
        std::string_view prometheus_subsystem,
        const std::map<std::string, std::string>& const_labels) const {
	std::string prometheus_metric_name_fully_qualified =
	        prometheus_qualifier(prometheus_namespace, prometheus_subsystem) +
	        std::string(metric.name) + "_";
	// Remove native libs unit suffixes if applicable.
	RE2::GlobalReplace(&prometheus_metric_name_fully_qualified,
	                   s_libs_metrics_units_suffix_pre_prometheus_text_conversion,
	                   "");
	prometheus_metric_name_fully_qualified +=
	        std::string(metrics_unit_name_mappings_prometheus[metric.unit]);
	return prometheus_exposition_text(
	        prometheus_metric_name_fully_qualified,
	        metric.name,
	        metrics_metric_type_name_mappings_prometheus[metric.metric_type],
	        metric_value_to_text(metric),
	        const_labels);
}

std::string prometheus_metrics_converter::convert_metric_to_text_prometheus(
        std::string_view metric_name,
        std::string_view prometheus_namespace,
        std::string_view prometheus_subsystem,
        const std::map<std::string, std::string>& const_labels) const {
	return prometheus_exposition_text(
	        prometheus_qualifier(prometheus_namespace, prometheus_subsystem) +
	                std::string(metric_name) + "_info",
	        metric_name,
	        "gauge",
	        "1",
	        const_labels);
}

void prometheus_metrics_converter::convert_metric_to_unit_convention(metrics_v2& metric) const {
	if((metric.unit == METRIC_VALUE_UNIT_MEMORY_BYTES ||
	    metric.unit == METRIC_VALUE_UNIT_MEMORY_KIBIBYTES) &&
	   (metric.type == METRIC_VALUE_TYPE_U32 || metric.type == METRIC_VALUE_TYPE_U64)) {
		if(metric.type == METRIC_VALUE_TYPE_U32) {
			metric.value.d = libs::metrics::convert_memory(metric.unit,
			                                               METRIC_VALUE_UNIT_MEMORY_BYTES,
			                                               metric.value.u32);
		} else if(metric.type == METRIC_VALUE_TYPE_U64) {
			metric.value.d = libs::metrics::convert_memory(metric.unit,
			                                               METRIC_VALUE_UNIT_MEMORY_BYTES,
			                                               metric.value.u64);
		}
		std::string metric_name_str(metric.name);
		RE2::GlobalReplace(&metric_name_str, s_libs_metrics_units_memory_suffix, "_bytes");
		strlcpy(metric.name, metric_name_str.c_str(), METRIC_NAME_MAX);
		metric.type = METRIC_VALUE_TYPE_D;
		metric.unit = METRIC_VALUE_UNIT_MEMORY_BYTES;
	} else if(metric.unit == METRIC_VALUE_UNIT_PERC && metric.type == METRIC_VALUE_TYPE_D) {
		metric.value.d = metric.value.d / 100.0;
		std::string metric_name_str(metric.name);
		RE2::GlobalReplace(&metric_name_str, s_libs_metrics_units_perc_suffix, "_ratio");
		strlcpy(metric.name, metric_name_str.c_str(), METRIC_NAME_MAX);
		metric.type = METRIC_VALUE_TYPE_D;
		metric.unit = METRIC_VALUE_UNIT_RATIO;
	}
}

libs_state_counters::libs_state_counters(const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
                                         sinsp_thread_manager* thread_manager):
        m_sinsp_stats_v2(sinsp_stats_v2),
        m_n_fds(0),
        m_n_threads(0) {
	if(thread_manager != nullptr) {
		m_n_threads = thread_manager->get_thread_count();
		threadinfo_map_t* threadtable = thread_manager->get_threads();
		if(threadtable != nullptr) {
			threadtable->loop([this](sinsp_threadinfo& tinfo) {
				sinsp_fdtable* fdtable = tinfo.get_fd_table();
				if(fdtable != nullptr) {
					this->m_n_fds += fdtable->size();
				}
				return true;
			});
		}
	}
}

std::vector<metrics_v2> libs_state_counters::to_metrics() {
	std::vector<metrics_v2> metrics;

	metrics.emplace_back(new_metric("n_threads",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_n_threads));
	metrics.emplace_back(new_metric("n_fds",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_n_fds));

	if(m_sinsp_stats_v2 == nullptr) {
		return metrics;
	}

	metrics.emplace_back(new_metric("n_noncached_fd_lookups",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_noncached_fd_lookups));
	metrics.emplace_back(new_metric("n_cached_fd_lookups",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_cached_fd_lookups));
	metrics.emplace_back(new_metric("n_failed_fd_lookups",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_failed_fd_lookups));
	metrics.emplace_back(new_metric("n_added_fds",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_added_fds));
	metrics.emplace_back(new_metric("n_removed_fds",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_removed_fds));
	metrics.emplace_back(new_metric("n_stored_evts",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_stored_evts));
	metrics.emplace_back(new_metric("n_store_evts_drops",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_store_evts_drops));
	metrics.emplace_back(new_metric("n_retrieved_evts",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_retrieved_evts));
	metrics.emplace_back(new_metric("n_retrieve_evts_drops",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_retrieve_evts_drops));
	metrics.emplace_back(new_metric("n_noncached_thread_lookups",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_noncached_thread_lookups));
	metrics.emplace_back(new_metric("n_cached_thread_lookups",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_cached_thread_lookups));
	metrics.emplace_back(new_metric("n_failed_thread_lookups",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_failed_thread_lookups));
	metrics.emplace_back(new_metric("n_added_threads",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_added_threads));
	metrics.emplace_back(new_metric("n_removed_threads",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_removed_threads));
	metrics.emplace_back(new_metric("n_drops_full_threadtable",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                m_sinsp_stats_v2->m_n_drops_full_threadtable));
	metrics.emplace_back(new_metric("n_missing_container_images",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_sinsp_stats_v2->m_n_missing_container_images));
	metrics.emplace_back(new_metric("n_containers",
	                                METRICS_V2_STATE_COUNTERS,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_sinsp_stats_v2->m_n_containers));
	return metrics;
}

void libs_metrics_collector::snapshot() {
	m_metrics.clear();
	if(!m_inspector) {
		return;
	}

	/*
	 * libscap metrics
	 */

	if((m_metrics_flags & METRICS_V2_KERNEL_COUNTERS) ||
	   (m_metrics_flags & METRICS_V2_LIBBPF_STATS) ||
	   (m_metrics_flags & METRICS_V2_KERNEL_COUNTERS_PER_CPU)) {
		uint32_t nstats = 0;
		int32_t rc = 0;
		// libscap metrics: m_metrics_flags are pushed down from consumers' input,
		// libbpf stats only collected when ENGINE_FLAG_BPF_STATS_ENABLED aka
		// `kernel.bpf_stats_enabled = 1`
		const metrics_v2* metrics_v2_scap_snapshot =
		        m_inspector->get_capture_stats_v2(m_metrics_flags, &nstats, &rc);
		if(metrics_v2_scap_snapshot && nstats > 0 && rc == 0) {
			// Move existing scap metrics raw buffer into m_metrics vector
			m_metrics.assign(metrics_v2_scap_snapshot, metrics_v2_scap_snapshot + nstats);
		}
	}

	/*
	 * libsinsp metrics
	 */
	if((m_metrics_flags & METRICS_V2_RESOURCE_UTILIZATION)) {
#ifdef __linux__
		const scap_agent_info* agent_info = m_inspector->get_agent_info();
		linux_resource_utilization resource_utilization(agent_info->start_time);
#else
		libsinsp_metrics resource_utilization;
#endif

		std::vector<metrics_v2> ru_metrics = resource_utilization.to_metrics();
		m_metrics.insert(m_metrics.end(), ru_metrics.begin(), ru_metrics.end());
	}

	if((m_metrics_flags & METRICS_V2_STATE_COUNTERS)) {
		libs_state_counters state_counters(m_sinsp_stats_v2, m_inspector->m_thread_manager.get());
		std::vector<metrics_v2> sc_metrics = state_counters.to_metrics();
		m_metrics.insert(m_metrics.end(), sc_metrics.begin(), sc_metrics.end());
	}

	/*
	 * plugins metrics
	 */
	if(m_metrics_flags & METRICS_V2_PLUGINS) {
		for(auto& p : m_inspector->get_plugin_manager()->plugins()) {
			std::vector<metrics_v2> plugin_metrics = p->get_metrics();
			m_metrics.insert(m_metrics.end(), plugin_metrics.begin(), plugin_metrics.end());
		}
	}
}

const std::vector<metrics_v2>& libs_metrics_collector::get_metrics() const {
	return m_metrics;
}

std::vector<metrics_v2>& libs_metrics_collector::get_metrics() {
	return m_metrics;
}

libs_metrics_collector::libs_metrics_collector(sinsp* inspector, uint32_t flags):
        m_inspector(inspector),
        m_metrics_flags(flags) {
	if(m_inspector != nullptr) {
		m_sinsp_stats_v2 = m_inspector->get_sinsp_stats_v2();
	} else {
		m_sinsp_stats_v2 = nullptr;
	}
}

}  // namespace libs::metrics
