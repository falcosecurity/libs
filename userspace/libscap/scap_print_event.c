
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

#include <stdio.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#if defined(_WIN32)
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

static void print_ipv4(int starting_index, char *valptr) {
	char ipv4_string[50];
	uint8_t *ipv4 = (uint8_t *)(valptr + starting_index);
	snprintf(ipv4_string, sizeof(ipv4_string), "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
	printf("- ipv4: %s\n", ipv4_string);
}

static void print_ipv6(int starting_index, char *valptr) {
	uint32_t ipv6[4] = {0, 0, 0, 0};
	ipv6[0] = *(uint32_t *)(valptr + starting_index);
	ipv6[1] = *(uint32_t *)(valptr + starting_index + 4);
	ipv6[2] = *(uint32_t *)(valptr + starting_index + 8);
	ipv6[3] = *(uint32_t *)(valptr + starting_index + 12);

	char ipv6_string[150];
	inet_ntop(AF_INET6, ipv6, ipv6_string, 150);
	printf("- ipv6: %s\n", ipv6_string);
}

static void print_unix_path(int starting_index, char *valptr) {
	printf("- unix path: %s\n", (char *)(valptr + starting_index));
}

static void print_port(int starting_index, char *valptr) {
	printf("- port: %d\n", *(uint16_t *)(valptr + starting_index));
}

static void print_parameter(int16_t num_param, scap_evt *ev, uint16_t offset) {
	uint16_t len =
	        *(uint16_t *)((char *)ev + sizeof(struct ppm_evt_hdr) + num_param * sizeof(uint16_t));
	char *valptr = (char *)ev + offset;

	if(len == 0) {
		printf("PARAM %d: is empty\n", num_param);
		return;
	}

	switch(g_event_info[ev->type].params[num_param].type) {
	case PT_FLAGS8:
		printf("PARAM %d: %X\n", num_param, *(uint8_t *)(valptr));
		break;

	case PT_FLAGS16:
		printf("PARAM %d: %X\n", num_param, *(uint16_t *)(valptr));
		break;

	case PT_FLAGS32:
		printf("PARAM %d: %X\n", num_param, *(uint32_t *)(valptr));
		break;

	case PT_INT8:
		printf("PARAM %d: %d\n", num_param, *(int8_t *)(valptr));
		break;

	case PT_INT16:
		printf("PARAM %d: %d\n", num_param, *(int16_t *)(valptr));
		break;

	case PT_INT32:
		printf("PARAM %d: %d\n", num_param, *(int32_t *)(valptr));
		break;

	case PT_INT64:
	case PT_ERRNO:
	case PT_PID:
		printf("PARAM %d: %ld\n", num_param, *(int64_t *)(valptr));
		break;

	case PT_UINT8:
	case PT_SIGTYPE:
	case PT_ENUMFLAGS8:
		printf("PARAM %d: %d\n", num_param, *(uint8_t *)(valptr));
		break;

	case PT_UINT16:
	case PT_SYSCALLID:
	case PT_ENUMFLAGS16:
		printf("PARAM %d: %d\n", num_param, *(uint16_t *)(valptr));
		break;

	case PT_UINT32:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
	case PT_MODE:
	case PT_ENUMFLAGS32:
		printf("PARAM %d: %d\n", num_param, *(uint32_t *)(valptr));
		break;

	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		printf("PARAM %d: %lu\n", num_param, *(uint64_t *)(valptr));
		break;

	case PT_FD:
		printf("PARAM %d: %d\n", num_param, *(int32_t *)(valptr));
		break;

	case PT_SOCKADDR: {
		printf("PARAM %d:\n", num_param);
		uint8_t sock_family = *(uint8_t *)(valptr);
		printf("- sock_family: %d\n", sock_family);
		switch(sock_family) {
		case PPM_AF_INET:
			/* ipv4 dest. */
			print_ipv4(1, valptr);

			/* port dest. */
			print_port(5, valptr);
			break;

		case PPM_AF_INET6:
			/* ipv6 dest. */
			print_ipv6(1, valptr);

			/* port dest. */
			print_port(17, valptr);
			break;

		case PPM_AF_UNIX:
			/* unix_path. */
			print_unix_path(1, valptr);
			break;

		default:
			printf("-  error\n");
			break;
		}
		break;
	}

	case PT_SOCKTUPLE: {
		printf("PARAM %d:\n", num_param);
		uint8_t sock_family = *(uint8_t *)(valptr);
		printf("- sock_family: %d\n", sock_family);
		switch(sock_family) {
		case PPM_AF_INET:
			/* ipv4 src. */
			print_ipv4(1, valptr);

			/* ipv4 dest. */
			print_ipv4(5, valptr);

			/* port src. */
			print_port(9, valptr);

			/* port dest. */
			print_port(11, valptr);
			break;

		case PPM_AF_INET6:
			/* ipv6 src. */
			print_ipv6(1, valptr);

			/* ipv6 dest. */
			print_ipv6(17, valptr);

			/* port src. */
			print_port(33, valptr);

			/* port dest. */
			print_port(35, valptr);
			break;

		case PPM_AF_UNIX:
			/* Here there are also some kernel pointers but right
			 * now we are not interested in catching them.
			 * 8 + 8 = 16 bytes
			 */

			/* unix_path. */
			print_unix_path(17, valptr);
			break;

		default:
			printf("-  error\n");
			break;
		}
		break;
	}

	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		printf("PARAM %d: %s\n", num_param, valptr);
		break;

	case PT_BYTEBUF:
	case PT_CHARBUFARRAY:
		printf("PARAM %d\n: ", num_param);
		for(int j = 0; j < len; j++) {
			printf("%c(%x)\n", *(char *)(valptr + j), *(char *)(valptr + j));
		}
		printf("\n");
		break;

	default:
		printf("PARAM %d: TYPE NOT KNOWN\n", num_param);
		break;
	}
}

static void scap_print_event_header(scap_evt *ev) {
	printf("----------------------- HEADER\n");
	printf("timestamp: %lu\n", ev->ts);
	printf("tid: %lu\n", ev->tid);
	printf("len: %d\n", ev->len);
	printf("type: %d\n", ev->type);
	printf("num params: %d\n", ev->nparams);
	printf("----------------------- \n");
}

static void scap_print_lengths(scap_evt *ev) {
	printf("----------------------- LEN ARRAY\n");
	uint16_t *lens16 = (uint16_t *)((char *)ev + sizeof(struct ppm_evt_hdr));
	for(int i = 0; i < ev->nparams; i++) {
		printf("param %d len: %d\n", i, lens16[i]);
	}
	if(ev->nparams == 0) {
		printf("- This event has no parameter\n");
	}
	printf("----------------------- \n");
}

static void scap_print_params(scap_evt *ev) {
	printf("----------------------- PARAMS\n");
	uint16_t offsets[PPM_MAX_EVENT_PARAMS + 1] = {0};
	offsets[0] = sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * ev->nparams;
	uint16_t *lens16 = (uint16_t *)((char *)ev + sizeof(struct ppm_evt_hdr));
	for(int i = 0; i < ev->nparams; i++) {
		print_parameter(i, ev, offsets[i]);
		offsets[i + 1] = offsets[i] + lens16[i];
	}
	if(ev->nparams == 0) {
		printf("- This event has no parameter\n");
	}
	printf("-----------------------\n");
}

void scap_print_event(scap_evt *ev, scap_print_info i) {
	switch(i) {
	case PRINT_HEADER:
		scap_print_event_header(ev);
		break;
	case PRINT_HEADER_LENGTHS:
		scap_print_event_header(ev);
		scap_print_lengths(ev);
		break;
	case PRINT_FULL:
		scap_print_event_header(ev);
		scap_print_lengths(ev);
		scap_print_params(ev);
		break;

	default:
		break;
	}
}
