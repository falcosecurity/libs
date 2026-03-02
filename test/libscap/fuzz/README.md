# libscap fuzz harnesses

This directory contains libFuzzer harnesses for `libscap`.

The initial harness (`fuzz_scap_event_decode.cc`) targets:

1. `scap_event_getinfo`
2. `scap_event_decode_params`

using a raw `scap_evt`-shaped byte buffer input.

## Build model

These files are intended to be consumed by external fuzzing integrations
(for example, OSS-Fuzz project build scripts) and are not wired into the
default `libs` CMake targets in this first pass.
