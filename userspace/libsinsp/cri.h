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

#include <memory>
#include <optional>
#include <string>

#ifndef MINIMAL_BUILD
#include <libsinsp/cri-v1alpha2.pb.h>
#include <libsinsp/cri-v1alpha2.grpc.pb.h>
#include <libsinsp/cri-v1.pb.h>
#include <libsinsp/cri-v1.grpc.pb.h>
#endif // MINIMAL_BUILD

#include <libsinsp/container_info.h>
#include <libsinsp/cgroup_limits.h>

#ifdef GRPC_INCLUDE_IS_GRPCPP
#	include <grpcpp/grpcpp.h>
#else
#	include <grpc++/grpc++.h>
#endif

namespace libsinsp {
namespace cri {

class cri_settings
{
public:
	cri_settings();
	~cri_settings();
	static cri_settings& get();

	static const std::vector<std::string>& get_cri_unix_socket_paths()
	{
		return get().m_cri_unix_socket_paths;
	}

	static void set_cri_unix_socket_paths(const std::vector<std::string>& v)
	{
		get().m_cri_unix_socket_paths = v;
	}

	static const int64_t& get_cri_timeout()
	{
		return get().m_cri_timeout;
	}

	static void set_cri_timeout(const int64_t& v)
	{
		get().m_cri_timeout = v;
	}

	static const int64_t& get_cri_size_timeout()
	{
		return get().m_cri_size_timeout;
	}

	static void set_cri_size_timeout(const int64_t& v)
	{
		get().m_cri_size_timeout = v;
	}

	static const sinsp_container_type& get_cri_runtime_type()
	{
		return get().m_cri_runtime_type;
	}

	static void set_cri_runtime_type(const sinsp_container_type& v)
	{
		get().m_cri_runtime_type = v;
	}

	static const std::string& get_cri_unix_socket_path()
	{
		return get().m_cri_unix_socket_path;
	}

	static void set_cri_unix_socket_path(const std::string& v)
	{
		get().m_cri_unix_socket_path = v;
	}

	static const bool& get_cri_extra_queries()
	{
		return get().m_cri_extra_queries;
	}

	static void set_cri_extra_queries(const bool& v)
	{
		get().m_cri_extra_queries = v;
	}

	static void add_cri_unix_socket_path(const std::string& v)
	{
		get().m_cri_unix_socket_paths.emplace_back(v);
	}

	static void clear_cri_unix_socket_paths()
	{
		get().m_cri_unix_socket_paths.clear();
	}

private:
	static std::unique_ptr<cri_settings> s_instance;

	cri_settings(const cri_settings&) = delete;
	cri_settings& operator=(const cri_settings&) = delete;

	std::vector<std::string> m_cri_unix_socket_paths;
	int64_t m_cri_timeout;
	int64_t m_cri_size_timeout;
	sinsp_container_type m_cri_runtime_type;
	std::string m_cri_unix_socket_path;
	bool m_cri_extra_queries;
};

class cri_api_v1alpha2
{
public:
	static constexpr const char *version = "v1alpha2";
	using RuntimeService = runtime::v1alpha2::RuntimeService;
	using ImageService = runtime::v1alpha2::ImageService;

	using ContainerStatusRequest = runtime::v1alpha2::ContainerStatusRequest;
	using ContainerStatusResponse = runtime::v1alpha2::ContainerStatusResponse;
	using ContainerStatus = runtime::v1alpha2::ContainerStatus;

	using ContainerStatsRequest = runtime::v1alpha2::ContainerStatsRequest;
	using ContainerStatsResponse = runtime::v1alpha2::ContainerStatsResponse;

	using ListContainersRequest = runtime::v1alpha2::ListContainersRequest;
	using ListContainersResponse = runtime::v1alpha2::ListContainersResponse;

	using ListImagesRequest = runtime::v1alpha2::ListImagesRequest;
	using ListImagesResponse = runtime::v1alpha2::ListImagesResponse;

	using PodSandboxStatusRequest = runtime::v1alpha2::PodSandboxStatusRequest;
	using PodSandboxStatusResponse = runtime::v1alpha2::PodSandboxStatusResponse;
	using PodSandboxStatus = runtime::v1alpha2::PodSandboxStatus;

	using VersionRequest = runtime::v1alpha2::VersionRequest;
	using VersionResponse = runtime::v1alpha2::VersionResponse;

	using NamespaceMode = runtime::v1alpha2::NamespaceMode;
	using MountPropagation = runtime::v1alpha2::MountPropagation;
};

class cri_api_v1
{
public:
	static constexpr const char *version = "v1";
	using RuntimeService = runtime::v1::RuntimeService;
	using ImageService = runtime::v1::ImageService;

	using ContainerStatusRequest = runtime::v1::ContainerStatusRequest;
	using ContainerStatusResponse = runtime::v1::ContainerStatusResponse;
	using ContainerStatus = runtime::v1::ContainerStatus;

	using ContainerStatsRequest = runtime::v1::ContainerStatsRequest;
	using ContainerStatsResponse = runtime::v1::ContainerStatsResponse;

	using ListContainersRequest = runtime::v1::ListContainersRequest;
	using ListContainersResponse = runtime::v1::ListContainersResponse;

	using ListImagesRequest = runtime::v1::ListImagesRequest;
	using ListImagesResponse = runtime::v1::ListImagesResponse;

	using PodSandboxStatusRequest = runtime::v1::PodSandboxStatusRequest;
	using PodSandboxStatusResponse = runtime::v1::PodSandboxStatusResponse;
	using PodSandboxStatus = runtime::v1::PodSandboxStatus;

	using VersionRequest = runtime::v1::VersionRequest;
	using VersionResponse = runtime::v1::VersionResponse;

	using NamespaceMode = runtime::v1::NamespaceMode;
	using MountPropagation = runtime::v1::MountPropagation;
};

template<class api> class cri_interface
{
public:

	cri_interface(const std::string& cri_path);

	/**
	 * @brief did we manage to connect to CRI and get the runtime name/version?
	 * @return true if successfully connected to CRI
	 */
	bool is_ok() const
	{
		return m_cri != nullptr;
	}

	/**
	 * @brief get the detected CRI runtime type
	 * @return one of CT_CRIO, CT_CONTAINERD, CT_CRI (for other CRI runtimes)
	 * 	corresponding to the CRI runtime type detected
	 */
	sinsp_container_type get_cri_runtime_type() const;

	//////////////////////////
	// CRI API calls helpers
	//////////////////////////

	/**
	 * @brief thin wrapper around CRI gRPC ContainerStatus call
	 * @param container_id container ID
	 * @param resp reference to the response of type api::ContainerStatusResponse (if the RPC is successful, it will be filled out)
	 * @return grpc::Status, status of the gRPC call
	 */
	grpc::Status get_container_status_resp(const std::string &container_id, typename api::ContainerStatusResponse &resp);

	/**
	 * @brief thin wrapper around CRI gRPC ContainerStats call
	 * @param container_id container ID
	 * @param resp reference to the response of type api::ContainerStatusResponse (if the RPC is successful, it will be filled out)
	 * @return grpc::Status, status of the gRPC call
	 */
	grpc::Status get_container_stats_resp(const std::string &container_id, typename api::ContainerStatsResponse &resp);

	/**
	 * @brief thin wrapper around CRI gRPC PodSandboxStatus call make request
	 * @param pod_sandbox_id pod sandbox ID
	 * @param resp reference to the response of type api::PodSandboxStatusResponse (if the RPC is successful, it will be filled out)
	 * @return grpc::Status, status of the gRPC call
	 */
	grpc::Status get_pod_sandbox_status_resp(const std::string &pod_sandbox_id, typename api::PodSandboxStatusResponse &resp);

	/**
	 * @brief get image id info from CRI via extra API calls
	 * @param image_ref the image ref from container metadata
	 * @return image id if found, empty string otherwise
	 */
	std::string get_container_image_id(const std::string &image_ref);

	/**
	 * @brief get the size of the container's writable layer via ContainerStat API calls
	 * @param container_id container ID
	 * @note currently unused
	 * @return the size of the writable layer in bytes. Returns an empty option on error
	 */
	std::optional<int64_t> get_writable_layer_size(const std::string &container_id);

	///////////////////////////////////////////////////////////
	// CRI response (ContainerStatusResponse) parsers helpers
	///////////////////////////////////////////////////////////

	/**
	 * @brief fill out status base fields
	 * @param status `status` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_base(const typename api::ContainerStatus &status, sinsp_container_info &container);

	/**
	 * @brief fill out container image information based on CRI response
	 * @param status `status` field of the ContainerStatusResponse
	 * @param root Json::Value of status.info() at "info" of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_image(const typename api::ContainerStatus &status,
			     const Json::Value &root,
			     sinsp_container_info &container);

	/**
	 * @brief fill out pod sandbox id, only valid when used w/ ContainerStatusResponse, not PodSandboxStatusResponse
	 * @param root Json::Value of status.info() at "info" of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_pod_sandbox_id_for_container(const Json::Value &root,
			     sinsp_container_info &container);

	/**
	 * @brief fill out container mount information based on CRI response
	 * @param status `status` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_mounts(const typename api::ContainerStatus &status, sinsp_container_info &container);

	/**
	 * @brief fill out container environment variables based on CRI response, valid for containerd only
	 * @param root Json::Value of status.info() at "info" of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 *
	 * Note: only containerd exposes this data
	 */
	bool parse_cri_env(const Json::Value &root, sinsp_container_info &container);

	/**
	 * @brief fill out extra image info based on CRI response, valid for containerd only
	 * @param root Json::Value of status.info() at "info" of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 *
	 * Note: only containerd exposes this data
	 */
	bool parse_cri_json_imageid(const Json::Value &root, sinsp_container_info &container);

	/**
	 * @brief fill out extra container info (e.g. resource limits) based on CRI response
	 * @param root Json::Value of status.info() at "info" of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_ext_container_info(const Json::Value &root, sinsp_container_info &container);

	/**
	 * @brief fill out extra container user info (e.g. configured uid) based on CRI response
	 * @param root Json::Value of status.info() at "info" of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 *
	 * Note: only containerd exposes this data
	 */
	bool parse_cri_user_info(const Json::Value &root, sinsp_container_info &container);

	/**
	 * @brief fill out container labels
	 * @param status `status` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_labels(const typename api::ContainerStatus &status, sinsp_container_info &container);

	///////////////////////////////////////////////////////////
	// CRI response (PodSandboxStatus) parsers helpers
	///////////////////////////////////////////////////////////

	/**
	 * @brief fill out status base fields, overloaded w/ PodSandboxStatus
	 * @param status `status` field of the PodSandboxStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_base(const typename api::PodSandboxStatus &status, sinsp_container_info &container);

	/**
	 * @brief fill out pod sandbox id, only valid when used w/ PodSandboxStatus, not ContainerStatusResponse
	 * @param container the container info to fill out
	 * @note effectively assigning the existing container.m_full_id as pod sandbox ID
	 * @return true if successful
	 */
	bool parse_cri_pod_sandbox_id_for_podsandbox(sinsp_container_info &container);

	/**
	 * @brief fill out container labels; overloaded w/ PodSandboxStatus
	 * @param status `status` field of the PodSandboxStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_labels(const typename api::PodSandboxStatus &status, sinsp_container_info &container);

	/**
	 * @brief fill out pod sandbox labels
	 * @param status `status` field of the PodSandboxStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_pod_sandbox_labels(const typename api::PodSandboxStatus &status, sinsp_container_info &container);

	/**
	 * @brief fill out pod sandbox network info
	 * @param status `status` field of the PodSandboxStatusResponse
	 * @param root Json::Value of status.info() at "info" of the PodSandboxStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_pod_sandbox_network(const typename api::PodSandboxStatus &status,
			     const Json::Value &root,
			     sinsp_container_info &container);


	/////////////////////////////
	// Generic parsers helpers
	/////////////////////////////

	/**
	 * @brief get the Json::Value of status.info() at "info"
	 * @param info status.info() Map
	 * @return Json::Value, can be null
	 */
	Json::Value get_info_jvalue(const google::protobuf::Map<std::string, std::string> &info);


	///////////////////////////////////////////////////////////////////
	// Main CRI parse entrypoint (make API calls and parse responses)
	///////////////////////////////////////////////////////////////////

	/**
	 * @brief fill in container metadata using the CRI API (`containerd` and `cri-o` container runtimes). 
	 * This is the main CRI parser calling each parse_* helper after making the respective CRI API call(s).
	 * @param key includes container_id, but container.m_id is used to make the CRI API calls
	 * @param container the container info to fill
	 * @return true on success, false on failure
	 */
	bool parse(const libsinsp::cgroup_limits::cgroup_limits_key &key, sinsp_container_info &container);

private:
	std::unique_ptr<typename api::RuntimeService::Stub> m_cri;
	std::unique_ptr<typename api::ImageService::Stub> m_cri_image;
	sinsp_container_type m_cri_runtime_type;
};

using cri_interface_v1alpha2 = cri_interface<cri_api_v1alpha2>;
using cri_interface_v1 = cri_interface<cri_api_v1>;
}
}
