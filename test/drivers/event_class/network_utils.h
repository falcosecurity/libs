#pragma once

/* Used in `SO_RCVTIMEO` test. */
#define SEC_FACTOR 1000000000
#define USEC_FACTOR 1000

/* Network components size. */
#define FAMILY_SIZE sizeof(uint8_t)
#define IPV4_SIZE sizeof(uint32_t)
#define IPV6_SIZE 16
#define PORT_SIZE sizeof(uint16_t)

/* This is used when we convert IPV4 or IPV6 addresses to a string. */
#define ADDRESS_LENGTH 100

/* Server queue length. */
#define QUEUE_LENGTH 2

/* IP ports
 * todo!: The distinction between ipv4 and ipv6 ports is not necessary.
 * at the moment we keep them just too avoid to touch many files.
 */
#define IP_PORT_DNS 53
#define IP_PORT_EMPTY 0
#define IP_PORT_EMPTY_STRING "0"
#define IP_PORT_CLIENT 51789
#define IP_PORT_CLIENT_STRING "51789"
#define IP_PORT_SERVER 52889
#define IP_PORT_SERVER_STRING "52889"

/*=============================== IPV4 ===========================*/

/* Empty endpoint */
#define IPV4_EMPTY "0.0.0.0"
#define IPV4_PORT_EMPTY IP_PORT_EMPTY
#define IPV4_PORT_EMPTY_STRING IP_PORT_EMPTY_STRING

/* IPv4 Client */
#define IPV4_CLIENT "127.0.21.34"
#define IPV4_PORT_CLIENT IP_PORT_CLIENT
#define IPV4_PORT_CLIENT_STRING IP_PORT_CLIENT_STRING

/* IPv4 Server */
#define IPV4_SERVER "127.59.21.35"
#define IPV4_PORT_SERVER IP_PORT_SERVER
#define IPV4_PORT_SERVER_STRING IP_PORT_SERVER_STRING

/*=============================== IPV4 ===========================*/

/*=============================== IPV6 ===========================*/

/* IPv6 Client */
#define IPV6_CLIENT "::ffff:127.0.0.4"
#define IPV6_PORT_CLIENT IP_PORT_CLIENT
#define IPV6_PORT_CLIENT_STRING IP_PORT_CLIENT_STRING

/* IPv6 Server */
#define IPV6_SERVER "::ffff:127.0.0.5"
#define IPV6_PORT_SERVER IP_PORT_SERVER
#define IPV6_PORT_SERVER_STRING IP_PORT_SERVER_STRING

/*=============================== IPV6 ===========================*/

/*=============================== UNIX ===========================*/

/* Max length socket unix path. */
#define MAX_SUN_PATH 108

/* Unix Client: the `xyzxe-` prefix is used to avoid name collisions */
#define UNIX_CLIENT "/tmp/xyzxe-client"

/* Unix Server: the `xyzxe-` prefix is used to avoid name collisions */
#define UNIX_SERVER "/tmp/xyzxe-server"

/*=============================== UNIX ===========================*/

/*=============================== SEND/RECEIVE ===========================*/

#define SHORT_MESSAGE "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"
#define SHORT_MESSAGE_LEN 61

#define LONG_MESSAGE                                                                               \
	"LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL" \
	"LLLLLLLLLLLLLLLLLLLLLLLLLLLL"
#define LONG_MESSAGE_LEN 121

// todo!: These macro are used in legacy network tests. They should be removed when we cleanup all
// nwtwork tests.
/* we have also the null terminator because in all our messages
 * (first, second, third) we have left the last byte for the
 * null terminator.
 *
 * Please note: if we left further space in our message the bpf
 * side will catch the entire length of the message, so will catch
 * all these extra bytes as `\0` bytes. Look at example here: the
 * second message has 38 bytes so the last 2 are `\0`.
 */
#define FIRST_MESSAGE_LEN 36
#define SECOND_MESSAGE_LEN 38
#define THIRD_MESSAGE_LEN 55
#define FULL_MESSAGE_LEN FIRST_MESSAGE_LEN + SECOND_MESSAGE_LEN + THIRD_MESSAGE_LEN
#define FULL_MESSAGE                                                                              \
	"hey! there is a first message here.\0hey! there is a second message here.\0\0hey! there is " \
	"a third message here."
#define NO_SNAPLEN_MESSAGE_LEN FIRST_MESSAGE_LEN + SECOND_MESSAGE_LEN
#define NO_SNAPLEN_MESSAGE \
	"hey! there is a first message here.\0hey! there is a second message here.\0"
#define MAX_RECV_BUF_SIZE 100

/*=============================== SEND/RECEIVE ===========================*/
