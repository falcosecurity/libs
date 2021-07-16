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
#include "connection.h"

#include "sinsp.h"
#include "sinsp_int.h"

namespace {

size_t docker_curl_write_callback(const char *ptr, size_t size, size_t nmemb, std::string *json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}

}

using namespace libsinsp::container_engine;

docker_connection::docker_connection():
	m_api_version("/v1.24"),
	m_curlm(nullptr)
{
	m_curlm = curl_multi_init();

	if(m_curlm)
	{
		curl_multi_setopt(m_curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX);
	}
}

docker_connection::~docker_connection()
{
	if(m_curlm)
	{
		curl_multi_cleanup(m_curlm);
		m_curlm = NULL;
	}
}

docker_connection::docker_response docker_connection::get_docker(const docker_lookup_request& request, const std::string& req_url, std::string &json)
{
	CURL* curl = curl_easy_init();
	if(!curl)
	{
		g_logger.format(sinsp_logger::SEV_WARNING,
				"docker_async (%s): Failed to initialize curl handle",
				req_url.c_str());
		return docker_response::RESP_ERROR;
	}

	auto docker_path = scap_get_host_root() + request.docker_socket;
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, docker_curl_write_callback);
	curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, docker_path.c_str());

	std::string url = "http://localhost" + m_api_version + req_url;

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): Fetching url",
			url.c_str());

	if(curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_easy_setopt(CURLOPT_URL) failed",
				url.c_str());

		curl_easy_cleanup(curl);
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	if(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_easy_setopt(CURLOPT_WRITEDATA) failed",
				url.c_str());
		curl_easy_cleanup(curl);
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(m_curlm, curl) != CURLM_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_multi_add_handle() failed",
				url.c_str());
		curl_easy_cleanup(curl);
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running;
		CURLMcode res = curl_multi_perform(m_curlm, &still_running);
		if(res != CURLM_OK)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): curl_multi_perform() failed",
					url.c_str());

			curl_multi_remove_handle(m_curlm, curl);
			curl_easy_cleanup(curl);
			ASSERT(false);
			return docker_response::RESP_ERROR;
		}

		if(still_running == 0)
		{
			break;
		}

		int numfds;
		res = curl_multi_wait(m_curlm, NULL, 0, 1000, &numfds);
		if(res != CURLM_OK)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): curl_multi_wait() failed",
					url.c_str());

			curl_multi_remove_handle(m_curlm, curl);
			curl_easy_cleanup(curl);
			ASSERT(false);
			return docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(m_curlm, curl) != CURLM_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_multi_remove_handle() failed",
				url.c_str());

		curl_easy_cleanup(curl);
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): curl_easy_getinfo(CURLINFO_RESPONSE_CODE) failed",
				url.c_str());

		curl_easy_cleanup(curl);
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	curl_easy_cleanup(curl);
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): http_code=%ld",
			url.c_str(), http_code);

	switch(http_code)
	{
	case 0: /* connection failed, apparently */
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): returning RESP_ERROR",
				url.c_str());
		return docker_response::RESP_ERROR;
	case 200:
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): returning RESP_OK",
				url.c_str());
		return docker_response::RESP_OK;
	default:
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): returning RESP_BAD_REQUEST",
				url.c_str());
		return docker_response::RESP_BAD_REQUEST;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): fallthrough, returning RESP_OK",
			url.c_str());

	return docker_response::RESP_OK;
}

