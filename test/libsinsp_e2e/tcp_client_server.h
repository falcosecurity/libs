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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <cassert>

#ifndef HELPER_32
#include <gtest/gtest.h>
#endif

#define SERVER_PORT 3555
#define SERVER_PORT_STR "3555"
#define FALSE 0

typedef enum iotype { READWRITE, SENDRECEIVE, READVWRITEV } iotype;

class tcp_server {
public:
	explicit tcp_server(iotype iot,
	                    bool use_shutdown = false,
	                    bool use_accept4 = false,
	                    uint32_t ntransactions = 1,
	                    bool exit_no_close = false) {
		m_tid = -1;
		m_iot = iot;
		m_use_shutdown = use_shutdown;
		m_use_accept4 = use_accept4;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	bool init() {
		struct sockaddr_in server_address;
		const int port = (m_exit_no_close) ? SERVER_PORT + 1 : SERVER_PORT;

		/* Create socket for incoming connections */
		if((m_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			perror("socket() failed");
			return false;
		}

		/* Construct local address structure */
		memset(&server_address, 0, sizeof(server_address)); /* Zero out structure */
		server_address.sin_family = AF_INET;                /* Internet address family */
		server_address.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
		server_address.sin_port = htons(port);              /* Local port */

		int yes = 1;
		if(setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt() failed");
			return false;
		}

		/* Bind to the local address */
		if(::bind(m_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
			perror("bind() failed");
			return false;
		}
		/* Mark the socket so it will listen for incoming connections */
		if(listen(m_socket, 1) < 0) {
			perror("listen() failed");
			return false;
		}
		std::cout << "SERVER UP" << std::endl;
		return true;
	}

	int run() {
		int error = 0;
		m_tid = syscall(SYS_gettid);
		struct sockaddr_in client_address;
		socklen_t client_len;
		do {
			/* Set the size of the in-out parameter */
			client_len = sizeof(client_address);

			/* Wait for a client to connect */
			if(m_use_accept4) {
				if((m_cl_socket =
				            accept4(m_socket, (struct sockaddr*)&client_address, &client_len, 0)) <
				   0) {
					perror("accept() failed");
					error++;
					break;
				}
			} else {
				if((m_cl_socket =
				            accept(m_socket, (struct sockaddr*)&client_address, &client_len)) < 0) {
					perror("accept() failed");
					error++;
					break;
				}
			}

			/* clntSock is connected to a client! */
			char echoBuffer[1024]; /* Buffer for echo string */
			int recvMsgSize;       /* Size of received message */
			for(uint32_t j = 0; j < m_ntransactions; j++) {
				if(m_iot == SENDRECEIVE) {
					if((recvMsgSize = recv(m_cl_socket, echoBuffer, sizeof(echoBuffer), 0)) < 0) {
						perror("recv() failed");
						error++;
						break;
					}

					if(send(m_cl_socket, echoBuffer, recvMsgSize, 0) != recvMsgSize) {
						perror("send() failed");
						error++;
						break;
					}
				} else if(m_iot == READWRITE || m_iot == READVWRITEV) {
					if((recvMsgSize = read(m_cl_socket, echoBuffer, sizeof(echoBuffer))) < 0) {
						perror("recv() failed");
						error++;
						break;
					}

					if(write(m_cl_socket, echoBuffer, recvMsgSize) != recvMsgSize) {
						perror("send() failed");
						error++;
						break;
					}
				}
			}
		} while(0);

		if(error) {
			// Close the server socket so that client will be notified
			if(m_use_shutdown) {
				shutdown(m_socket, SHUT_RDWR);
			} else {
				close(m_socket);
			}
		} else {
			if(!m_exit_no_close) {
				if(m_use_shutdown) {
					if(m_cl_socket != -1) {
						shutdown(m_cl_socket, SHUT_WR);
					}
					if(m_socket != -1) {
						shutdown(m_socket, SHUT_RDWR);
					}
				} else {
					if(m_cl_socket != -1) {
						close(m_cl_socket);
					}
					if(m_socket != -1) {
						close(m_socket);
					}
				}
			}
		}
		return error;
	}

	int64_t get_tid() const { return m_tid; }

	void shutdown_server() {
		if(m_socket != -1) {
			shutdown(m_socket, SHUT_RDWR);
		}
	}

private:
	int m_socket = -1;
	int m_cl_socket = -1;
	int64_t m_tid;
	iotype m_iot;
	bool m_use_shutdown;
	bool m_use_accept4;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
};

class tcp_client {
public:
	tcp_client(uint32_t server_ip_address,
	           iotype iot,
	           const std::string& payload = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM",
	           uint32_t ntransactions = 1,
	           bool exit_no_close = false) {
		m_tid = -1;
		m_server_ip_address = server_ip_address;
		m_iot = iot;
		m_payload = payload;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	bool init() {
		struct sockaddr_in server_address;
		const int port = (m_exit_no_close) ? SERVER_PORT + 1 : SERVER_PORT;

		/* Create a reliable, stream socket using TCP */
		if((m_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			perror("socket() failed");
			return false;
		}

		/* Construct the server address structure */
		memset(&server_address, 0, sizeof(server_address));   /* Zero out structure */
		server_address.sin_family = AF_INET;                  /* Internet address family */
		server_address.sin_addr.s_addr = m_server_ip_address; /* Server IP address */
		server_address.sin_port = htons(port);                /* Server port */

		/* Establish the connection to the server */
		if(connect(m_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
			perror("connect() failed");
			return false;
		}

		std::cout << "CLIENT UP" << std::endl;
		return true;
	}

	int run() {
		m_tid = syscall(SYS_gettid);
		char buffer[m_payload.size() + 1];
		int bytes_received;
		int error = 0;

		for(uint32_t j = 0; j < m_ntransactions; j++) {
			/* Send the string to the server */
			if(m_iot == SENDRECEIVE) {
				if(send(m_socket, m_payload.c_str(), m_payload.length(), 0) !=
				   (ssize_t)m_payload.length()) {
					perror("send() sent a different number of bytes than expected");
					error++;
					break;
				}

				if((bytes_received = recv(m_socket, buffer, m_payload.length(), 0)) <= 0) {
					perror("recv() failed or connection closed prematurely");
					error++;
					break;
				}

				buffer[bytes_received] = '\0'; /* Terminate the string! */
				if(strcmp(m_payload.c_str(), buffer) != 0) {
					perror("SENDRECEIVE buffer mismatch");
					error++;
					break;
				}
			} else if(m_iot == READWRITE) {
				if(write(m_socket, m_payload.c_str(), m_payload.length()) !=
				   (ssize_t)m_payload.length()) {
					perror("send() sent a different number of bytes than expected");
					error++;
					break;
				}

				if((bytes_received = read(m_socket, buffer, m_payload.length())) <= 0) {
					perror("recv() failed or connection closed prematurely");
					error++;
					break;
				}

				buffer[bytes_received] = '\0'; /* Terminate the string! */
				if(strcmp(m_payload.c_str(), buffer) != 0) {
					perror("READWRITE buffer mismatch");
					error++;
					break;
				}
			} else if(m_iot == READVWRITEV) {
				int wv_count;
				char msg1[m_payload.length() / 3 + 1];
				char msg2[m_payload.length() / 3 + 1];
				char msg3[m_payload.length() / 3 + 1];
				struct iovec wv[3];

				memcpy(msg1,
				       m_payload.substr(0, m_payload.length() / 3).c_str(),
				       m_payload.length() / 3);
				memcpy(msg2,
				       m_payload.substr(m_payload.length() / 3, m_payload.length() * 2 / 3).c_str(),
				       m_payload.length() / 3);
				memcpy(msg3,
				       m_payload.substr(m_payload.length() * 2 / 3, m_payload.length()).c_str(),
				       m_payload.length() / 3);

				wv[0].iov_base = msg1;
				wv[1].iov_base = msg2;
				wv[2].iov_base = msg3;
				wv[0].iov_len = m_payload.length() / 3;
				wv[1].iov_len = m_payload.length() / 3;
				wv[2].iov_len = m_payload.length() / 3;
				wv_count = 3;

				if(writev(m_socket, wv, wv_count) != (ssize_t)m_payload.length()) {
					perror("send() sent a different number of bytes than expected");
					error++;
					break;
				}

				if((bytes_received = readv(m_socket, wv, wv_count)) <= 0) {
					perror("recv() failed or connection closed prematurely");
					error++;
					break;
				}
			}
		}

		if((!m_exit_no_close || error) && m_socket != -1) {
			close(m_socket);
		}
		return 0;
	}

	int64_t get_tid() const { return m_tid; }

private:
	int m_socket = -1;
	uint32_t m_server_ip_address;
	iotype m_iot;
	int64_t m_tid;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
	std::string m_payload;
};
