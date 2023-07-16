/*
Copyright (C) 2023 The Falco Authors.
This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.
*/

#pragma once

/* Possible snaplen */
#define SNAPLEN 80
#define SNAPLEN_EXTENDED 2000
#define SNAPLEN_TRACERS_ENABLED 4096
#define SNAPLEN_FULLCAPTURE_PORT 16000
#define SNAPLEN_MAX 65000

/* Deep packet inspection logic */
#define DPI_LOOKAHEAD_SIZE 16
#define PPM_PORT_MYSQL 3306
#define PPM_PORT_POSTGRES 5432
#define PPM_PORT_STATSD 8125
#define PPM_PORT_MONGODB 27017

/* HTTP */
#define BPF_HTTP_GET 0x20544547
#define BPF_HTTP_POST 0x54534F50
#define BPF_HTTP_PUT 0x20545550
#define BPF_HTTP_DELETE 0x454C4544
#define BPF_HTTP_TRACE 0x43415254
#define BPF_HTTP_CONNECT 0x4E4E4F43
#define BPF_HTTP_OPTIONS 0x4954504F
#define BPF_HTTP_PREFIX 0x50545448

/* Convert seconds to nanoseconds */
#define SECOND_TO_NS 1000000000ULL
