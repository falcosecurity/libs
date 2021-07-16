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

#include "dragent_win_hal_public.h"

using namespace libsinsp::container_engine;

docker_connection::docker_connection():
	m_api_version("/v1.30")
{
}

docker_connection::~docker_connection()
{
}

std::string docker_connection::build_request(const std::string &url)
{
	return "GET " + m_api_version + url + " HTTP/1.1\r\nHost: docker\r\n\r\n";
}

docker_connection::docker_response docker_connection::get_docker(const docker_lookup_request& request, const std::string& url, std::string &json)
{
	const char* response = NULL;
	bool qdres = wh_query_docker(m_inspector->get_wmi_handle(),
				     (char*)url.c_str(),
				     &response);
	if(qdres == false)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	json = response;
	if(strncmp(json.c_str(), "HTTP/1.0 200 OK", sizeof("HTTP/1.0 200 OK") -1))
	{
		return docker_response::RESP_BAD_REQUEST;
	}

	size_t pos = json.find("{");
	if(pos == string::npos)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	json = json.substr(pos);

	return docker_response::RESP_OK;
}

