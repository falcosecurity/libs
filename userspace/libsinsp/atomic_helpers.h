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

// Lightweight relaxed atomic helpers for thread-safety on shared fields
// without requiring std::atomic (which would break the state framework's
// typeinfo system). These use GCC/Clang __atomic builtins that TSAN
// understands natively.

template<typename T>
inline T load_relaxed(const T& val) {
	return __atomic_load_n(const_cast<T*>(&val), __ATOMIC_RELAXED);
}

template<typename T>
inline void store_relaxed(T& dest, T val) {
	__atomic_store_n(&dest, val, __ATOMIC_RELAXED);
}

template<typename T>
inline T fetch_or_relaxed(T& dest, T val) {
	return __atomic_fetch_or(&dest, val, __ATOMIC_RELAXED);
}

template<typename T>
inline T fetch_and_relaxed(T& dest, T val) {
	return __atomic_fetch_and(&dest, val, __ATOMIC_RELAXED);
}
