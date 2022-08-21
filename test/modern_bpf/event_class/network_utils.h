#pragma once

/* Network components size. */
#define FAMILY_SIZE sizeof(uint8_t)
#define IPV4_SIZE sizeof(uint32_t)
#define IPV6_SIZE 16
#define PORT_SIZE sizeof(uint16_t)

/* This is used when we convert IPV4 or IPV6 addresses to a string. */
#define ADDRESS_LENGTH 100

/* Server queue length. */
#define QUEUE_LENGTH 2

/*=============================== IPV4 ===========================*/

/* IPv4 Client */
#define IPV4_CLIENT "127.0.21.34"
#define IPV4_PORT_CLIENT 51789
#define IPV4_PORT_CLIENT_STRING "51789"

/* IPv4 Server */
#define IPV4_SERVER "127.0.21.35"
#define IPV4_PORT_SERVER 52889
#define IPV4_PORT_SERVER_STRING "52889"

/*=============================== IPV4 ===========================*/

/*=============================== IPV6 ===========================*/

/* IPv6 Client */
#define IPV6_CLIENT "::ffff:127.0.0.4"
#define IPV6_PORT_CLIENT 51790
#define IPV6_PORT_CLIENT_STRING "51790"

/* IPv6 Server */
#define IPV6_SERVER "::ffff:127.0.0.5"
#define IPV6_PORT_SERVER 52890
#define IPV6_PORT_SERVER_STRING "52890"

/*=============================== IPV6 ===========================*/

/*=============================== UNIX ===========================*/

/* Max length socket unix path. */
#define MAX_SUN_PATH 108

/* Unix Client: the `xyzxe-` prefix is used to avoid name collisions */
#define UNIX_CLIENT "/tmp/xyzxe-client"

/* Unix Server: the `xyzxe-` prefix is used to avoid name collisions */
#define UNIX_SERVER "/tmp/xyzxe-server"

/*=============================== UNIX ===========================*/
