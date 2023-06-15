/*
Copyright (C) 2021 The Falco Authors.

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
#include "cri-v1alpha2.pb.h"
#include "cri-v1alpha2.grpc.pb.h"
#include "cri-v1.pb.h"
#include "cri-v1.grpc.pb.h"
#endif // MINIMAL_BUILD

#include "container_info.h"
#include "cgroup_limits.h"

#ifdef GRPC_INCLUDE_IS_GRPCPP
#	include <grpcpp/grpcpp.h>
#else
#	include <grpc++/grpc++.h>
#endif

namespace libsinsp {
namespace cri {

// these shouldn't be globals but we still need references to *the* CRI runtime
extern std::vector<std::string> s_cri_unix_socket_paths;
extern int64_t s_cri_timeout;
// TODO: drop these 2 below
extern std::string s_cri_unix_socket_path;
extern sinsp_container_type s_cri_runtime_type;
extern bool s_cri_extra_queries;

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

	/**
	 * @brief thin wrapper around CRI gRPC ContainerStatus call
	 * @param container_id container ID
	 * @param resp reference to the response (if the RPC is successful, it will be filled out)
	 * @return status of the gRPC call
	 */
	grpc::Status get_container_status(const std::string &container_id, typename api::ContainerStatusResponse &resp);

	/**
	 * @brief thin wrapper around CRI gRPC ContainerStats call
	 * @param container_id container ID
	 * @param resp reference to the response (if the RPC is successful, it will be filled out)
	 * @return status of the gRPC call
	 */
	grpc::Status get_container_stats(const std::string &container_id, typename api::ContainerStatsResponse &resp);

	/**
	 * @brief get the size of the container's writable layer
	 * @param container_id container ID
	 * @return the size of the writable layer in bytes. Returns an empty option on error
	 */
	std::optional<int64_t> get_writable_layer_size(const std::string &container_id);

	/**
	 * @brief fill out container image information based on CRI response
	 * @param status `status` field of the ContainerStatusResponse
	 * @param info `info` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_image(const typename api::ContainerStatus &status,
			     const google::protobuf::Map<std::string, std::string> &info,
			     sinsp_container_info &container);

	/**
	 * @brief fill out container mount information based on CRI response
	 * @param status `status` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_mounts(const typename api::ContainerStatus &status, sinsp_container_info &container);

	/**
	 * @brief fill out container environment variables based on CRI response
	 * @param info the `info` key of the `info` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 *
	 * Note: only containerd exposes this data
	 */
	bool parse_cri_env(const Json::Value &info, sinsp_container_info &container);

	/**
	 * @brief fill out extra image info based on CRI response
	 * @param info the `info` key of the `info` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 *
	 * Note: only containerd exposes this data
	 */
	bool parse_cri_json_image(const Json::Value &info, sinsp_container_info &container);

	/**
	 * @brief fill out extra container info (e.g. resource limits) based on CRI response
	 * @param info the `info` key of the `info` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 */
	bool parse_cri_ext_container_info(const Json::Value &info, sinsp_container_info &container);

	/**
	 * @brief fill out extra container user info (e.g. configured uid) based on CRI response
	 * @param info the `info` key of the `info` field of the ContainerStatusResponse
	 * @param container the container info to fill out
	 * @return true if successful
	 *
	 * Note: only containerd exposes this data
	 */
	bool parse_cri_user_info(const Json::Value &info, sinsp_container_info &container);

	/**
	 * @brief check if the passed container ID is a pod sandbox (pause container)
	 * @param container_id the container ID to check
	 * @return true if it's a pod sandbox
	 */
	bool is_pod_sandbox(const std::string &container_id);

	/**
	 * @brief get pod IP address
	 * @param resp initialized api::PodSandboxStatusResponse of the pod sandbox
	 * @return the IP address if possible, 0 otherwise (e.g. when the pod uses host netns)
	 */
	uint32_t get_pod_sandbox_ip(typename api::PodSandboxStatusResponse &resp);

	/**
	 * @brief get unparsed JSON string with cni result of the pod sandbox from PodSandboxStatusResponse info()
	 * field.
	 * @param resp initialized api::PodSandboxStatusResponse of the pod sandbox
	 * @param cniresult initialized cniresult
	 */
	void get_pod_info_cniresult(typename api::PodSandboxStatusResponse &resp, std::string &cniresult);

	/**
	 * @brief make request and get PodSandboxStatusResponse and grpc::Status.
	 * @param pod_sandbox_id ID of the pod sandbox
	 * @param resp initialized api::PodSandboxStatusResponse of the pod sandbox
	 * @param status initialized grpc::Status
	 */
	void get_pod_sandbox_resp(const std::string &pod_sandbox_id, typename api::PodSandboxStatusResponse &resp,
				  grpc::Status &status);

	/**
	 * @brief get container IP address if possible, 0 otherwise (e.g. when the pod uses host netns),
	 *  get unparsed JSON string with cni result of the pod sandbox from PodSandboxStatusResponse info() field.
	 * @param container_id the container ID
	 * @param container_ip initialized container_ip
	 * @param cniresult initialized cniresult
	 *
	 * This method first finds the pod ID, then gets the IP address and also checks for cni result
	 * of the pod sandbox container
	 */
	void get_container_ip(const std::string &container_id, uint32_t &container_ip, std::string &cniresult);

	/**
	 * @brief get image id info from CRI
	 * @param image_ref the image ref from container metadata
	 * @return image id if found, empty string otherwise
	 */
	std::string get_container_image_id(const std::string &image_ref);

	/**
	 * @brief fill in container metadata using the CRI API
	 * @param key the async lookup key (includes container_id)
	 * @param container the container info to fill
	 * @return true on success, false on failure
	 */
	bool parse(const libsinsp::cgroup_limits::cgroup_limits_key &key, sinsp_container_info &container);

private:
	bool parse_containerd(const typename api::ContainerStatusResponse &status, sinsp_container_info &container);

	std::unique_ptr<typename api::RuntimeService::Stub> m_cri;
	std::unique_ptr<typename api::ImageService::Stub> m_cri_image;
	sinsp_container_type m_cri_runtime_type;
};

using cri_interface_v1alpha2 = cri_interface<cri_api_v1alpha2>;
using cri_interface_v1 = cri_interface<cri_api_v1>;
}
}
