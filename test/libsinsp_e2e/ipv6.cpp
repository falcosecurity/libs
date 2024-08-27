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

#include "scap_file_reader.h"
#include "libsinsp_test_var.h"

#include <gtest/gtest.h>

#include <libsinsp/sinsp.h>

#include <functional>
#include <memory>
#include <set>
#include <string>

typedef std::function<bool(std::string& output)> validate_func_t;

class ipv6_filtercheck_test : public testing::Test
{
protected:
	struct cstring_comp
	{
		bool operator()(const char* s1, const char* s2) const { return strcmp(s1, s2) < 0; }
	};

	typedef std::set<const char*, cstring_comp> cstringset_t;

	virtual void SetUp() {}

	virtual void TearDown() {}

	virtual void read_file(const char* filename,
	                       const char* extra_filter,
	                       std::function<void(sinsp_evt*)> evtcb,
	                       bool generate_ip_net_filters = true)
	{
		m_inspector = file_reader.setup_read_file();

		m_socket_connected = false;
		m_check_local_remote = false;
		m_check_is_server = false;

		if (generate_ip_net_filters)
		{
			gen_ip_net_filters();
		}

		std::string filter =
		    "evt.type in (socket, connect, recvfrom, sendto, close, accept, connect, bind, read, "
		    "write, poll) and evt.dir=< and fd.type!=file and fd.type!=unix and fd.type!=file and "
		    "fd.type!=pipe";
		if (extra_filter)
		{
			filter += " and ";
			filter += extra_filter;
		}

		file_reader.run_inspector(filename, filter, evtcb);
	}

	void check_ipv6_filterchecks(sinsp_evt* evt)
	{
		std::string full_output;
		std::string full =
		    "*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type "
		    "%evt.info";
		sinsp_evt_formatter(m_inspector.get(), full, m_filterlist).tostring(evt, &full_output);

		verify_filtercheck(evt, "*%fd.type", "ipv6", full_output);
		verify_filtercheck(evt, "*%fd.typechar", "6", full_output);
		verify_filtercheck(evt, "*%fd.sockfamily", "ip", full_output);

		if (m_socket_connected)
		{
			verify_filtercheck(evt, "*%fd.name", m_conn_names, full_output);

			verify_filtercheck(evt, "*%fd.cip", m_client_ip, full_output);
			verify_filtercheck(evt, "*%fd.sip", m_server_ip, full_output);

			verify_filtercheck(evt, "*%fd.cport", m_client_port, full_output);
			verify_filtercheck(evt, "*%fd.sport", m_server_ports, full_output);

			ASSERT_TRUE(m_ip_client_filter->run(evt))
			    << "fd.ip=" << m_client_ip
			    << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_ip_server_filter->run(evt))
			    << "fd.ip=" << m_server_ip
			    << " did not match event. Full event output: " << full_output;

			ASSERT_TRUE(m_net_client_filter->run(evt))
			    << "fd.net=" << m_client_net
			    << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_net_server_filter->run(evt))
			    << "fd.net=" << m_server_net
			    << " did not match event. Full event output: " << full_output;

			ASSERT_TRUE(m_cnet_filter->run(evt))
			    << "fd.cnet=" << m_client_net
			    << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_snet_filter->run(evt))
			    << "fd.snet=" << m_server_net
			    << " did not match event. Full event output: " << full_output;

			verify_filtercheck(evt, "*%fd.cproto", m_client_proto, full_output);
			verify_filtercheck(evt, "*%fd.sproto", m_server_protos, full_output);

			verify_filtercheck(evt, "*%fd.l4proto", m_l4proto, full_output);

			if (m_check_is_server)
			{
				verify_filtercheck(evt, "*%fd.is_server", m_is_server, full_output);
			}
		}

		if (m_check_local_remote)
		{
			verify_filtercheck(evt, "*%fd.lip", m_client_ip, full_output);
			verify_filtercheck(evt, "*%fd.rip", m_server_ip, full_output);

			verify_filtercheck(evt, "*%fd.lport", m_client_port, full_output);
			verify_filtercheck(evt, "*%fd.rport", m_server_ports, full_output);

			ASSERT_TRUE(m_lnet_filter->run(evt))
			    << "fd.lnet=" << m_client_net
			    << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_rnet_filter->run(evt))
			    << "fd.rnet=" << m_server_net
			    << " did not match event. Full event output: " << full_output;

			verify_filtercheck(evt, "*%fd.lproto", m_client_proto, full_output);
			verify_filtercheck(evt, "*%fd.rproto", m_server_protos, full_output);
		}
	}

	void verify_filtercheck(sinsp_evt* evt,
	                        const char* format,
	                        const char* expectedc,
	                        std::string full_output)
	{
		cstringset_t expected;
		expected.insert(expectedc);

		verify_filtercheck(evt, format, expected, full_output);
	}

	void verify_filtercheck(sinsp_evt* evt,
	                        const char* format,
	                        std::string& expecteds,
	                        std::string full_output)
	{
		cstringset_t expected;
		expected.insert(expecteds.c_str());

		verify_filtercheck(evt, format, expected, full_output);
	}

	void verify_filtercheck(sinsp_evt* evt,
	                        const char* cformat,
	                        cstringset_t& expected,
	                        std::string full_output)
	{
		std::string output;
		std::string format = cformat;

		sinsp_evt_formatter(m_inspector.get(), format, m_filterlist).tostring(evt, &output);

		auto it = expected.find(output.c_str());

		ASSERT_TRUE(it != expected.end())
		    << " Result of format " << cformat
		    << " did not match any expected value. Full event output: " << full_output;
	}

	void gen_ip_net_filters()
	{
		auto inspector = file_reader.setup_read_file();
		sinsp_filter_compiler ip_client(inspector.get(), "fd.ip=" + m_client_ip);
		m_ip_client_filter = std::move(ip_client.compile());

		sinsp_filter_compiler ip_server(inspector.get(), "fd.ip=" + m_server_ip);
		m_ip_server_filter = std::move(ip_server.compile());

		sinsp_filter_compiler net_client(inspector.get(), "fd.net=" + m_client_net);
		m_net_client_filter = std::move(net_client.compile());

		sinsp_filter_compiler net_server(inspector.get(), "fd.net=" + m_server_net);
		m_net_server_filter = std::move(net_server.compile());

		sinsp_filter_compiler cnet(inspector.get(), "fd.cnet=" + m_client_net);
		m_cnet_filter = std::move(cnet.compile());

		sinsp_filter_compiler snet(inspector.get(), "fd.snet=" + m_server_net);
		m_snet_filter = std::move(snet.compile());

		sinsp_filter_compiler lnet(inspector.get(), "fd.lnet=" + m_client_net);
		m_lnet_filter = std::move(lnet.compile());

		sinsp_filter_compiler rnet(inspector.get(), "fd.rnet=" + m_server_net);
		m_rnet_filter = std::move(rnet.compile());
	}

	std::string m_client_ip;
	std::string m_server_ip;
	std::string m_client_port;
	cstringset_t m_server_ports;
	std::string m_client_net;
	std::string m_server_net;
	std::string m_client_proto;
	cstringset_t m_server_protos;
	cstringset_t m_conn_names;
	std::string m_l4proto;
	std::string m_is_server;

	sinsp_filter_check_list m_filterlist;
	std::shared_ptr<sinsp_filter> m_ip_client_filter;
	std::shared_ptr<sinsp_filter> m_ip_server_filter;
	std::shared_ptr<sinsp_filter> m_net_client_filter;
	std::shared_ptr<sinsp_filter> m_net_server_filter;
	std::shared_ptr<sinsp_filter> m_cnet_filter;
	std::shared_ptr<sinsp_filter> m_snet_filter;
	std::shared_ptr<sinsp_filter> m_lnet_filter;
	std::shared_ptr<sinsp_filter> m_rnet_filter;
	std::shared_ptr<sinsp> m_inspector;
	scap_file_reader file_reader;
	bool m_socket_connected;
	bool m_check_local_remote;
	bool m_check_is_server;
};

TEST_F(ipv6_filtercheck_test, curl_google_dnsreq)
{
	m_client_ip = "2600:1f18:262c:6542:9aa6:df7a:9a47:d29e";
	m_server_ip = "2001:4860:4860::8888";
	m_client_port = "40251";
	m_server_ports = {"53"};
	m_client_net = "2600:1f18:262c:6542::/64";
	m_server_net = "2001:4860:4860::/64";
	m_client_proto = "40251";
	m_server_protos = {"domain"};
	m_conn_names = {"2600:1f18:262c:6542:9aa6:df7a:9a47:d29e:40251->2001:4860:4860::8888:domain"};
	m_l4proto = "udp";
	m_is_server = "false";

	read_file(LIBSINSP_TEST_CAPTURES_PATH "/curl_google.scap",
	          "thread.tid=17498",
	          [this](sinsp_evt* evt)
	          {
		          std::string evname = std::string(evt->get_name());

		          // Once we see a connect or bind, we can assume the
		          // socket is connected and it's possible to get
		          // client/server and local/remote information.
		          if (evname == "connect" || evname == "bind")
		          {
			          m_socket_connected = true;
			          m_check_local_remote = true;
			          m_check_is_server = true;
		          }

		          check_ipv6_filterchecks(evt);
	          });
}

TEST_F(ipv6_filtercheck_test, curl_google_www)
{
	m_client_ip = "2600:1f18:262c:6542:9aa6:df7a:9a47:d29e";
	m_server_ip = "2607:f8b0:4004:802::2004";
	m_client_port = "37140";
	m_server_ports = {"80"};
	m_client_net = "2600:1f18:262c:6542::/64";
	m_server_net = "2607:f8b0:4004:802::/64";
	m_client_proto = "37140";
	m_server_protos = {"http"};
	m_conn_names = {"2600:1f18:262c:6542:9aa6:df7a:9a47:d29e:37140->2607:f8b0:4004:802::2004:http"};
	m_l4proto = "tcp";
	m_is_server = "false";

	read_file(LIBSINSP_TEST_CAPTURES_PATH "/curl_google.scap",
	          "thread.tid=17497",
	          [this](sinsp_evt* evt)
	          {
		          std::string evname = std::string(evt->get_name());

		          // Once we see a connect or bind, we can assume the
		          // socket is connected and it's possible to get
		          // client/server and local/remote information.
		          if (evname == "connect" || evname == "bind")
		          {
			          m_socket_connected = true;
			          m_check_local_remote = true;
			          m_check_is_server = true;
		          }

		          check_ipv6_filterchecks(evt);
	          });
}

TEST_F(ipv6_filtercheck_test, single_ipv6_conn_client)
{
	m_client_ip = "2001:db8::4";
	m_server_ip = "2001:db8::3";
	m_client_port = "54405";

	// Some /etc/services map port 1234 to search-agent, so we
	// allow both.
	m_server_ports = {"1234", "search-agent"};

	m_client_net = "2001:db8::/64";
	m_server_net = "2001:db8::/64";
	m_client_proto = "54405";
	m_server_protos = {"1234", "search-agent"};
	m_conn_names = {"2001:db8::4:54405->2001:db8::3:1234",
	                "2001:db8::4:54405->2001:db8::3:search-agent"};
	m_l4proto = "tcp";
	m_is_server = "false";

	read_file(LIBSINSP_TEST_CAPTURES_PATH "/single_ipv6_conn.scap",
	          "proc.pid=25888",
	          [this](sinsp_evt* evt)
	          {
		          std::string evname = std::string(evt->get_name());

		          // Once we see a connect, we can assume the
		          // socket is connected and it's possible to get
		          // client/server information. However, we can *not*
		          // get local/remote information as this connection was
		          // done between two ips on the same local interface.
		          if (evname == "connect")
		          {
			          m_socket_connected = true;
		          }

		          check_ipv6_filterchecks(evt);
	          });
}

TEST_F(ipv6_filtercheck_test, single_ipv6_conn_server)
{
	m_client_ip = "2001:db8::4";
	m_server_ip = "2001:db8::3";
	m_client_port = "54405";
	m_server_ports = {"1234", "search-agent"};
	m_client_net = "2001:db8::/64";
	m_server_net = "2001:db8::/64";
	m_client_proto = "54405";
	m_server_protos = {"1234", "search-agent"};
	m_conn_names = {"2001:db8::4:54405->2001:db8::3:1234",
	                "2001:db8::4:54405->2001:db8::3:search-agent"};
	m_l4proto = "tcp";
	m_is_server = "server";

	read_file(LIBSINSP_TEST_CAPTURES_PATH "/single_ipv6_conn.scap",
	          "proc.pid=25886",
	          [this](sinsp_evt* evt)
	          {
		          std::string evname = std::string(evt->get_name());

		          // Once we see a connect, we can assume the
		          // socket is connected and it's possible to get
		          // client/server information. However, we can *not*
		          // get local/remote information as this connection was
		          // done between two ips on the same local interface.
		          if (evname == "connect")
		          {
			          m_socket_connected = true;
		          }

		          check_ipv6_filterchecks(evt);
	          });
}

TEST_F(ipv6_filtercheck_test, test_ipv6_client)
{
	// test_ipv6_client.cpp does the following:
	//  1. sendto() on an unconnected socket to ::1
	//  2. connect to ::1, port 2345
	//  3. send() on the connected socket (to ::1)
	//  4. connect to google dns server, port 53
	//  5. send() on the connected socket (to google dns server)
	//  6. sendto() back to ::1, port 2345
	//
	// Some /etc/services map port 2345 to dbm, so we allow both.

	// The test verifies that the addresses/ports on the socket
	// change properly for the connects/sendtos.

	enum state_t
	{
		sendto_unconnected,
		send_connected,
		send_reconnected,
		sendto_reconnected,
		done
	};

	state_t state = sendto_unconnected;

	read_file(
	    LIBSINSP_TEST_CAPTURES_PATH "/test_ipv6_client.scap",
	    "proc.name=test_ipv6_clien",
	    [&](sinsp_evt* evt)
	    {
		    std::string evname = std::string(evt->get_name());

		    std::string full_output;
		    std::string full =
		        "*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type "
		        "%evt.info";
		    sinsp_evt_formatter(m_inspector.get(), full, m_filterlist).tostring(evt, &full_output);

		    cstringset_t unconnected_names = {"::1:0->::1:2345", "::1:0->::1:dbm"};
		    cstringset_t connected_names = {"::1:38255->::1:2345", "::1:38255->::1:dbm"};
		    cstringset_t reconnected_names = {"::1:38255->::1:2345", "::1:38255->::1:dbm"};

		    if (evname == "send" || evname == "sendto")
		    {
			    switch (state)
			    {
			    case sendto_unconnected:
				    verify_filtercheck(evt, "*%fd.name", unconnected_names, full_output);
				    state = send_connected;
				    break;
			    case send_connected:
				    verify_filtercheck(evt, "*%fd.name", connected_names, full_output);
				    state = send_reconnected;
				    break;
			    case send_reconnected:
				    verify_filtercheck(evt,
				                       "*%fd.name",
				                       "::1:38255->2001:4860:4860::8888:domain",
				                       full_output);
				    state = sendto_reconnected;
				    break;
			    case sendto_reconnected:
				    verify_filtercheck(evt, "*%fd.name", reconnected_names, full_output);
				    state = done;
				    break;
			    case done:
				    break;
			    }
		    }
	    },
	    false);

	ASSERT_TRUE(state == done);
}
