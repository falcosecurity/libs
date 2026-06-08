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
// typeinfo system).
//
// On GCC/Clang these use __atomic builtins that TSAN understands natively.
// On MSVC, loads/stores use volatile access (which provides acquire/release
// semantics by default), and RMW operations use _Interlocked* intrinsics.
//
// GCC may emit false-positive -Wstringop-overflow ("region of size 0") when
// these templates are inlined through multiple layers (e.g. into thread_manager
// or threadinfo). The referent is always a properly-sized scalar; suppress
// the warning only around the builtin calls.

#ifdef _MSC_VER
#include <intrin.h>
#endif

template<typename T>
inline T load_relaxed(const T& val) {
#ifdef _MSC_VER
	return *reinterpret_cast<const volatile T*>(&val);
#else
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	T r = __atomic_load_n(const_cast<T*>(&val), __ATOMIC_RELAXED);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
	return r;
#endif
}

template<typename T>
inline void store_relaxed(T& dest, T val) {
#ifdef _MSC_VER
	*reinterpret_cast<volatile T*>(&dest) = val;
#else
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	__atomic_store_n(&dest, val, __ATOMIC_RELAXED);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif
}

template<typename T>
inline T fetch_or_relaxed(T& dest, T val) {
#ifdef _MSC_VER
	if constexpr(sizeof(T) == 8) {
		return static_cast<T>(_InterlockedOr64(reinterpret_cast<volatile long long*>(&dest),
		                                       static_cast<long long>(val)));
	} else if constexpr(sizeof(T) == 4) {
		return static_cast<T>(
		        _InterlockedOr(reinterpret_cast<volatile long*>(&dest), static_cast<long>(val)));
	}
#else
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	T r = __atomic_fetch_or(&dest, val, __ATOMIC_RELAXED);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
	return r;
#endif
}

template<typename T>
inline T fetch_and_relaxed(T& dest, T val) {
#ifdef _MSC_VER
	if constexpr(sizeof(T) == 8) {
		return static_cast<T>(_InterlockedAnd64(reinterpret_cast<volatile long long*>(&dest),
		                                        static_cast<long long>(val)));
	} else if constexpr(sizeof(T) == 4) {
		return static_cast<T>(
		        _InterlockedAnd(reinterpret_cast<volatile long*>(&dest), static_cast<long>(val)));
	}
#else
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	T r = __atomic_fetch_and(&dest, val, __ATOMIC_RELAXED);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
	return r;
#endif
}

template<typename T>
inline T fetch_add_relaxed(T& dest, T val) {
#ifdef _MSC_VER
	if constexpr(sizeof(T) == 8) {
		return static_cast<T>(
		        _InterlockedExchangeAdd64(reinterpret_cast<volatile long long*>(&dest),
		                                  static_cast<long long>(val)));
	} else if constexpr(sizeof(T) == 4) {
		return static_cast<T>(_InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&dest),
		                                              static_cast<long>(val)));
	}
#else
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	T r = __atomic_fetch_add(&dest, val, __ATOMIC_RELAXED);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
	return r;
#endif
}

template<typename T>
inline T fetch_sub_relaxed(T& dest, T val) {
#ifdef _MSC_VER
	if constexpr(sizeof(T) == 8) {
		return static_cast<T>(
		        _InterlockedExchangeAdd64(reinterpret_cast<volatile long long*>(&dest),
		                                  -static_cast<long long>(val)));
	} else if constexpr(sizeof(T) == 4) {
		return static_cast<T>(_InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&dest),
		                                              -static_cast<long>(val)));
	}
#else
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	T r = __atomic_fetch_sub(&dest, val, __ATOMIC_RELAXED);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
	return r;
#endif
}
