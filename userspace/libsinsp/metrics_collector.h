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

#pragma once

#include <libscap/metrics_v2.h>
#include <libscap/scap_machine_info.h>
#include <libsinsp/threadinfo.h>
#include <libscap/strl.h>
#include <cmath>
#include <memory>
#include <optional>
#include <string_view>
#include <map>

struct sinsp_stats_v2 {
	///@(
	/** fdtable state related counters, unit: count. */
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_failed_fd_lookups;
	uint64_t m_n_added_fds;
	uint64_t m_n_removed_fds;
	///@)
	///@(
	/** evt parsing related counters, unit: count. */
	uint64_t m_n_stored_evts;
	uint64_t m_n_store_evts_drops;
	uint64_t m_n_retrieved_evts;
	uint64_t m_n_retrieve_evts_drops;
	///@)
	///@(
	/** threadtable state related counters, unit: count. */
	uint64_t m_n_noncached_thread_lookups;
	uint64_t m_n_cached_thread_lookups;
	uint64_t m_n_failed_thread_lookups;
	uint64_t m_n_added_threads;
	uint64_t m_n_removed_threads;
	///@)
	uint32_t m_n_drops_full_threadtable;  ///< Number of drops due to full threadtable, unit: count.
	uint32_t
	        m_n_missing_container_images;  ///<  Number of cached containers (cgroups) without
	                                       ///<  container info such as image, hijacked
	                                       ///<  sinsp_container_manager::remove_inactive_containers()
	                                       ///<  -> every flush snapshot update, unit: count.
	uint32_t m_n_containers;  ///<  Number of containers (cgroups) currently cached by
	                          ///<  sinsp_container_manager, hijacked
	                          ///<  sinsp_container_manager::remove_inactive_containers() -> every
	                          ///<  flush snapshot update, unit: count.
};

namespace libs::metrics {

template<typename T>
double convert_memory(metrics_v2_value_unit source_unit, metrics_v2_value_unit dest_unit, T val) {
	double factor = 1;
	switch(source_unit) {
	case METRIC_VALUE_UNIT_MEMORY_BYTES:
		factor = 1;
		break;
	case METRIC_VALUE_UNIT_MEMORY_KIBIBYTES:
		factor = 1024.;
		break;
	case METRIC_VALUE_UNIT_MEMORY_MEGABYTES:
		factor = 1024. * 1024.;
		break;
	default:
		return 0;
	}

	double bytes_val = val * factor;
	switch(dest_unit) {
	case METRIC_VALUE_UNIT_MEMORY_BYTES:
		return bytes_val;
	case METRIC_VALUE_UNIT_MEMORY_KIBIBYTES:
		return std::round((bytes_val / 1024.) * 10.) / 10.;  // round to 1 decimal
	case METRIC_VALUE_UNIT_MEMORY_MEGABYTES:
		return std::round((bytes_val / 1024. / 1024.) * 10.) / 10.;  // round to 1 decimal
	default:
		return 0;
	}
}

class metrics_converter {
public:
	virtual ~metrics_converter() = default;

	virtual std::string convert_metric_to_text(const metrics_v2& metric) const;

	virtual void convert_metric_to_unit_convention(metrics_v2& metric) const = 0;
};

// Subclass for Prometheus-specific metric conversion
class prometheus_metrics_converter : public metrics_converter {
public:
	/*!
	\brief Method to convert a metrics_v2 metric to the text-based Prometheus exposition format.
	 *
	 * Reference:
	https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
	 * Note: The design idea is to expose Prometheus metrics by piping text-based formats to new
	line-delimited fields
	 * exposed at /metrics in Falco's existing HTTP webserver (w/ optional mTLS support),
	eliminating the need for implementing
	 * a complete Prometheus client.
	 *
	 * We exclusively support counter and gauge Prometheus metric types, covering metrics from
	kernel driver tracepoints
	 * to linsinsp and client metrics. Introducing a registry seems excessive, especially given the
	dynamic nature of the final
	 * metric string names, such as variations in tracepoints across architectures.
	 * Considering the simplistic use case, adding another dependency to the project does not seem
	justified. Furthermore, for C++
	 * (compared to Go for example), there appear to be fewer formal client library projects
	available. Plus, we need to think
	 * about stability and long-term support before adding any new dependency.
	 *
	 * The final fully qualified Prometheus metric name partially follows
	https://prometheus.io/docs/practices/naming/
	 * Prepend namespace and subsystem with "_" delimiter to create a fully qualified metric name
	according to
	 * https://pkg.go.dev/github.com/prometheus/client_golang/prometheus#Opts + append unit with "_"
	delimiter
	 * We do not strictly follow and enforce the concept of base_units, but guarantee no units are
	mixed per unique
	 * `prometheus_metric_name_fully_qualified`
	 *
	 * We are monitoring updates wrt
	https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md
	 *
	 * Example:
	 *
	 * # HELP testns_falco_n_threads_total https://falco.org/docs/metrics/
	 * # TYPE testns_falco_n_threads_total gauge
	 * testns_falco_n_threads_total{raw_name="n_threads",example_key1="example1",example_key2="example2"} 12
	 * # HELP testns_falco_memory_rss_megabytes https://falco.org/docs/metrics/
	 * # TYPE testns_falco_memory_rss_megabytes gauge
	 * testns_falco_memory_rss_megabytes{raw_name="memory_rss",example_key1="example1",example_key2="example2"} 350.000000
	 *
	 * This method is a work in progress.
	 *
	 * @param metric metrics_v2 metric
	 * @param prometheus_namespace first component of `prometheus_metric_name_fully_qualified`
	(optional)
	 * @param prometheus_subsystem second component of `prometheus_metric_name_fully_qualified`
	(optional)
	 * @param const_labels map of additional labels (rarely used for a metrics_v2 metric)
	 * @return Complete new line delimited text-based Prometheus exposition format metric string
	 * w/ a `prometheus_metric_name_fully_qualified` - optional components prepended to and unit
	appended to.
	 * 3-lines including # HELP and # TYPE lines followed by the metric line, raw metric name always
	present as label.
	*/
	std::string convert_metric_to_text_prometheus(
	        const metrics_v2& metric,
	        std::string_view prometheus_namespace = "",
	        std::string_view prometheus_subsystem = "",
	        const std::map<std::string, std::string>& const_labels = {}) const;

	/*!
	\brief Overloaded method to convert a pseudo-metric / software version like metric_name to the
	text-based Prometheus exposition format.
	 *
	 * Note: Instead of using const_labels, which is a rare use case according to
	 * https://prometheus.io/docs/instrumenting/writing_exporters/#target-labels-not-static-scraped-labels,
	 * exposing an overload to support metrics similar to
	https://www.robustperception.io/exposing-the-software-version-to-prometheus/.
	 * This approach is applicable to https://falco.org/docs/metrics/, such as Falco's "Base Fields"
	like
	 * falco.kernel_release and falco.version.
	 *
	 * Example:
	 *
	 * # HELP testns_falco_kernel_release_info https://falco.org/docs/metrics/
	 * # TYPE testns_falco_kernel_release_info gauge
	 * testns_falco_kernel_release_info{raw_name="kernel_release",kernel_release="6.6.7-200.fc39.x86_64"} 1
	 *
	 * @param metric_name raw metric name
	 * @param prometheus_namespace first component of `prometheus_metric_name_fully_qualified`
	(optional)
	 * @param prometheus_subsystem second component of `prometheus_metric_name_fully_qualified`
	(optional)
	 * @param const_labels map of additional labels (typically used in software version like
	metrics)
	 * @return Complete new line delimited text-based Prometheus exposition format metric string
	 * w/ a `prometheus_metric_name_fully_qualified` - optional components prepended to and unit
	appended to.
	 * 3-lines including # HELP and # TYPE lines followed by the metric line, raw metric name always
	present as label.
	 */
	std::string convert_metric_to_text_prometheus(
	        std::string_view metric_name,
	        std::string_view prometheus_namespace = "",
	        std::string_view prometheus_subsystem = "",
	        const std::map<std::string, std::string>& const_labels = {}) const;

	/*!
	 * \brief Method to convert metric units to Prometheus base units.
	 *
	 * \note Metric names shall be updated within this method, and the respective
	 * Prometheus-compliant unit suffix shall be added. Prometheus compliance means every metric
	 * name has a unit suffix, see https://prometheus.io/docs/practices/naming/ or
	 * https://prometheus.io/docs/practices/naming/#base-units. We conform to the best practices
	 * except for keeping libbpf stats metrics and timestamps in nanoseconds to avoid precision loss
	 * when converting them to seconds. Please note that, for example, even cAdvisor sometimes
	 * deviates from the standards, e.g., `container_memory_rss` instead of
	 * `container_memory_rss_bytes`. `metric.unit` is also modified and always matches the metric
	 * name unit suffix.
	 *
	 * In summary, effectively for Falco/libs, it just means converting all memory to bytes and CPU
	 * usage to a ratio.
	 */
	void convert_metric_to_unit_convention(metrics_v2& metric) const override;
};

// Subclass for output_rule-specific metric conversion
class output_rule_metrics_converter : public metrics_converter {
public:
	/*!
	\brief Method to convert metric units of memory-related metrics to mb
	 *
	 * \note metrics names w/ unit suffix shall be updated within this method.
	 * `metric.unit` is also modified and always matches the metric name unit suffix if applicable.
	 *
	*/
	void convert_metric_to_unit_convention(metrics_v2& metric) const override;
};

class libsinsp_metrics {
public:
	template<typename T>
	static void set_metric_value(metrics_v2& metric, metrics_v2_value_type type, T val) {
		switch(type) {
		case METRIC_VALUE_TYPE_U32:
			metric.value.u32 = static_cast<uint32_t>(val);
			break;
		case METRIC_VALUE_TYPE_S32:
			metric.value.s32 = static_cast<int32_t>(val);
			break;
		case METRIC_VALUE_TYPE_U64:
			metric.value.u64 = static_cast<uint64_t>(val);
			break;
		case METRIC_VALUE_TYPE_S64:
			metric.value.s64 = static_cast<int64_t>(val);
			break;
		case METRIC_VALUE_TYPE_D:
			metric.value.d = static_cast<double>(val);
			break;
		case METRIC_VALUE_TYPE_F:
			metric.value.f = static_cast<float>(val);
			break;
		case METRIC_VALUE_TYPE_I:
			metric.value.i = static_cast<int>(val);
			break;
		default:
			break;
		}
	}

	/*!
	\brief Method to create a new metrics_v2
	*/
	template<typename T>
	static inline metrics_v2 new_metric(const char* name,
	                                    uint32_t flags,
	                                    metrics_v2_value_type type,
	                                    metrics_v2_value_unit unit,
	                                    metrics_v2_metric_type metric_type,
	                                    T val) {
		metrics_v2 metric;
		strlcpy(metric.name, name, METRIC_NAME_MAX);
		metric.flags = flags;
		metric.type = type;
		metric.unit = unit;
		metric.metric_type = metric_type;
		set_metric_value(metric, type, val);
		return metric;
	}

	libsinsp_metrics() = default;
	libsinsp_metrics(const libsinsp_metrics&) = default;
	libsinsp_metrics(libsinsp_metrics&&) = delete;
	libsinsp_metrics& operator=(const libsinsp_metrics&) = default;
	libsinsp_metrics& operator=(libsinsp_metrics&&) = delete;
	virtual ~libsinsp_metrics() = default;
	virtual std::vector<metrics_v2> to_metrics() { return std::vector<metrics_v2>(); };
};

class libs_state_counters : libsinsp_metrics {
public:
	libs_state_counters(const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
	                    sinsp_thread_manager* thread_manager);

	std::vector<metrics_v2> to_metrics() override;

private:
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;

	uint64_t m_n_fds;  ///< Total number of fds currently stored across all threadtables associated
	                   ///< with each active thread in the sinsp state thread table, unit: count.
	uint64_t m_n_threads;  ///< Total number of threads currently stored in the sinsp state thread
	                       ///< table, unit: count.
};

class libs_metrics_collector {
public:
	libs_metrics_collector(sinsp* inspector, uint32_t flags);

	/*!
	\brief Method to fill up m_metrics_buffer with metrics; refreshes m_metrics with up-to-date
	metrics on each call
	*/
	void snapshot();

	/*!
	\brief Method to get a const reference to m_metrics vector
	*/
	const std::vector<metrics_v2>& get_metrics() const;

	/*!
	\brief Method to get a non-const reference to m_metrics vector
	*/
	std::vector<metrics_v2>& get_metrics();

private:
	sinsp* m_inspector;
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	uint32_t m_metrics_flags = METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS |
	                           METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS |
	                           METRICS_V2_PLUGINS | METRICS_V2_KERNEL_COUNTERS_PER_CPU;
	std::vector<metrics_v2> m_metrics;
};

}  // namespace libs::metrics
