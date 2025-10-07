// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <cstdint>

// This namespace contains simple helpers allowing to manipulate packed data.
namespace packed {

namespace in6_socktuple {
inline const uint8_t *sip(const uint8_t *tuple) {
	return tuple + 1;
}
inline const uint8_t *ipv4_mapped_sip(const uint8_t *tuple) {
	return tuple + 13;
}
inline const uint8_t *sport(const uint8_t *tuple) {
	return tuple + 17;
}
inline const uint8_t *dip(const uint8_t *tuple) {
	return tuple + 19;
}
inline const uint8_t *ipv4_mapped_dip(const uint8_t *tuple) {
	return tuple + 31;
}
inline const uint8_t *dport(const uint8_t *tuple) {
	return tuple + 35;
}
}  // namespace in6_socktuple

namespace in_socktuple {
inline const uint8_t *sip(const uint8_t *tuple) {
	return tuple + 1;
}
inline const uint8_t *sport(const uint8_t *tuple) {
	return tuple + 5;
}
inline const uint8_t *dip(const uint8_t *tuple) {
	return tuple + 7;
}
inline const uint8_t *dport(const uint8_t *tuple) {
	return tuple + 11;
}
}  // namespace in_socktuple

namespace un_socktuple {
inline const uint8_t *source(const uint8_t *tuple) {
	return tuple + 1;
}
inline const uint8_t *dest(const uint8_t *tuple) {
	return tuple + 9;
}
inline const uint8_t *dpath(const uint8_t *tuple) {
	return tuple + 17;
}
}  // namespace un_socktuple

namespace in6_sockaddr {
inline const uint8_t *ip(const uint8_t *addr) {
	return addr + 1;
}
inline const uint8_t *ipv4_mapped_ip(const uint8_t *addr) {
	return addr + 13;
}
inline const uint8_t *port(const uint8_t *addr) {
	return addr + 17;
}

}  // namespace in6_sockaddr

namespace in_sockaddr {
inline const uint8_t *ip(const uint8_t *addr) {
	return addr + 1;
}
inline const uint8_t *port(const uint8_t *addr) {
	return addr + 5;
}
}  // namespace in_sockaddr

namespace un_sockaddr {
inline const uint8_t *dpath(const uint8_t *addr) {
	return addr + 1;
}
}  // namespace un_sockaddr

}  // namespace packed
