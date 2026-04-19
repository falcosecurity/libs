#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

from pathlib import Path
import re
import struct
import sys


# Build the deterministic seed corpus used by fuzz_scap_event_decode.
# The script copies selected real events extracted from sample captures and
# adds synthetic events that exercise decoder paths missing from those captures.

REGULAR_EVENT_NAMES = [
    "PPME_GENERIC_X",
    "PPME_SYSCALL_OPEN_X",
    "PPME_SYSCALL_READ_X",
    "PPME_SOCKET_SENDTO_X",
    "PPME_SYSCALL_CLOSE_X",
    "PPME_SYSCALL_WRITE_X",
    "PPME_SOCKET_CONNECT_X",
    "PPME_PROCEXIT_1_E",
    "PPME_SYSCALL_CLONE_20_X",
    "PPME_SYSCALL_EXECVE_19_X",
]

LARGE_PAYLOAD_EVENT_NAMES = [
    "PPME_PLUGINEVENT_E",
    "PPME_CONTAINER_JSON_2_E",
    "PPME_ASYNCEVENT_E",
]

REAL_EVENT_SELECTIONS = [
    ("curl_google", 159, 64, "real_curl_google_type159_len64.bin"),
    ("curl_google", 161, 106, "real_curl_google_type161_len106.bin"),
    ("curl_google", 1, 34, "real_curl_google_type1_len34.bin"),
    ("curl_google", 293, 2394, "real_curl_google_type293_len2394.bin"),
    ("curl_google", 2, 32, "real_curl_google_type2_len32.bin"),
    ("curl_google", 7, 134, "real_curl_google_type7_len134.bin"),
    ("test_ipv6_client", 165, 74, "real_test_ipv6_client_type165_len74.bin"),
    ("test_ipv6_client", 31, 99, "real_test_ipv6_client_type31_len99.bin"),
]


def load_event_codes(header_path, required_names):
    """Load public event-code values needed by the synthetic seed builder."""
    event_table = {}
    pattern = re.compile(r"^\s*(PPME_[A-Z0-9_]+)\s*=\s*(\d+),\s*$")

    for line in header_path.read_text().splitlines():
        match = pattern.match(line)
        if match:
            event_table[match.group(1)] = int(match.group(2))

    missing = sorted(required_names - event_table.keys())
    if missing:
        raise SystemExit(f"Missing event codes in {header_path}: {', '.join(missing)}")
    return event_table


def copy_real_events(corpus_dir, extracted_root):
    """Copy the selected real capture events into the final corpus."""
    for source_dir, ev_type, ev_len, out_name in REAL_EVENT_SELECTIONS:
        matches = sorted((extracted_root / source_dir).glob(f"evt_*_type{ev_type}_len{ev_len}.bin"))
        if not matches:
            raise SystemExit(f"Missing extracted event for type={ev_type} len={ev_len} in {source_dir}")
        # The extractor already prepends the harness control byte, so these
        # files can be used as direct harness input without another conversion.
        (corpus_dir / out_name).write_bytes(matches[0].read_bytes())


class SyntheticEventBuilder:
    """Build scap_evt-shaped synthetic seeds with the harness control byte."""

    def __init__(self, event_codes):
        self.event_codes = event_codes

    def pack_event(
        self,
        event_name,
        nparams,
        length_entries,
        payload=b"",
        # Deterministic, recognizable filler values for synthetic timestamp and thread id fields.
        ts=0x1122334455667788,
        tid=0x8877665544332211,
    ):
        """Pack a scap_evt header, length table, and payload."""
        if len(length_entries) != nparams:
            raise SystemExit(
                f"length_entries mismatch for type={event_name}: expected {nparams}, got {len(length_entries)}"
            )
        event_type = self.event_codes[event_name]
        is_large = event_name in LARGE_PAYLOAD_EVENT_NAMES
        length_fmt = "<" + ("I" if is_large else "H") * nparams
        lengths = struct.pack(length_fmt, *length_entries)
        total_len = 26 + len(lengths) + len(payload)
        header = struct.pack("<QQIHI", ts, tid, total_len, event_type, nparams)
        return header + lengths + payload

    def pack_seed(self, control, event_name, nparams, length_entries, payload=b""):
        """Prefix a packed event with the fuzzer-only control byte."""
        return bytes([control]) + self.pack_event(event_name, nparams, length_entries, payload)

    def build_events(self):
        """Return synthetic seeds for regular, large-payload, and clamp paths."""
        pack_seed = self.pack_seed
        return {
            # Regular events (16-bit length table).
            "synthetic_generic_x_exact_2params.bin": pack_seed(
                0x01, "PPME_GENERIC_X", 2, [2, 2], b"\x4b\x00\x0a\x00",
            ),
            "synthetic_open_x_zero_params.bin": pack_seed(
                0x05, "PPME_SYSCALL_OPEN_X", 6, [0] * 6,
            ),
            "synthetic_open_x_header_nparams8.bin": pack_seed(
                0x05, "PPME_SYSCALL_OPEN_X", 8, [0] * 8,
            ),
            "synthetic_read_x_schema_clamp.bin": pack_seed(
                0x59, "PPME_SYSCALL_READ_X", 6, [0] * 6,
            ),
            "synthetic_sendto_x_mixed_sizes.bin": pack_seed(
                0x0D, "PPME_SOCKET_SENDTO_X", 5, [0, 8, 0, 4, 2], bytes(range(14)),
            ),
            "synthetic_close_x_exact.bin": pack_seed(
                0x11,
                "PPME_SYSCALL_CLOSE_X",
                2,
                [4, 8],
                struct.pack("<i", -1) + struct.pack("<q", 3),
            ),
            "synthetic_close_x_schema_clamp.bin": pack_seed(
                0x61, "PPME_SYSCALL_CLOSE_X", 7, [0] * 7,
            ),
            "synthetic_write_x_exact.bin": pack_seed(
                0x15, "PPME_SYSCALL_WRITE_X", 4, [0] * 4,
            ),
            "synthetic_write_x_schema_clamp.bin": pack_seed(
                0x65, "PPME_SYSCALL_WRITE_X", 9, [0] * 9,
            ),
            "synthetic_connect_x_exact.bin": pack_seed(
                0x19, "PPME_SOCKET_CONNECT_X", 4, [0] * 4,
            ),
            "synthetic_connect_x_schema_clamp.bin": pack_seed(
                0x69, "PPME_SOCKET_CONNECT_X", 10, [0] * 10,
            ),
            "synthetic_procexit_exact.bin": pack_seed(
                0x1D,
                "PPME_PROCEXIT_1_E",
                5,
                [4, 4, 1, 1, 8],
                struct.pack("<iibb", 0, -1, 9, 0) + struct.pack("<q", 1),
            ),
            "synthetic_procexit_schema_clamp.bin": pack_seed(
                0x6D, "PPME_PROCEXIT_1_E", 11, [0] * 11,
            ),
            "synthetic_clone_x_exact.bin": pack_seed(
                0x21, "PPME_SYSCALL_CLONE_20_X", 21, [0] * 21,
            ),
            "synthetic_clone_x_schema_clamp.bin": pack_seed(
                0x71, "PPME_SYSCALL_CLONE_20_X", 28, [0] * 28,
            ),
            "synthetic_execve_x_exact.bin": pack_seed(
                0x25, "PPME_SYSCALL_EXECVE_19_X", 31, [0] * 31,
            ),
            "synthetic_execve_x_schema_clamp.bin": pack_seed(
                0x75, "PPME_SYSCALL_EXECVE_19_X", 32, [0] * 32,
            ),
            # Large-payload events (32-bit length table).
            "synthetic_pluginevent_exact_valid.bin": pack_seed(
                0x02, "PPME_PLUGINEVENT_E", 2, [4, 16], struct.pack("<I", 42) + bytes(range(16)),
            ),
            "synthetic_pluginevent_large_header_nparams4.bin": pack_seed(
                0x4A, "PPME_PLUGINEVENT_E", 4, [4, 8, 0, 0], struct.pack("<I", 99) + bytes(range(8)),
            ),
            "synthetic_container_json_exact_valid.bin": pack_seed(
                0x06, "PPME_CONTAINER_JSON_2_E", 1, [20], b'{"id":"test1234567"}',
            ),
            "synthetic_container_json_large_header_nparams3.bin": pack_seed(
                0x4E, "PPME_CONTAINER_JSON_2_E", 3, [0] * 3,
            ),
            "synthetic_asyncevent_large_valid.bin": pack_seed(
                0x0A, "PPME_ASYNCEVENT_E", 3, [4, 10, 8], struct.pack("<I", 7) + b"metaevent\x00" + bytes(range(8)),
            ),
            "synthetic_asyncevent_schema_clamp.bin": pack_seed(
                0x52,
                "PPME_ASYNCEVENT_E",
                6,
                [4, 10, 8, 0, 0, 0],
                struct.pack("<I", 7) + b"metaevent\x00" + bytes(range(8)),
            ),
        }


def write_synthetic_events(corpus_dir, event_codes):
    """Write all synthetic seeds and return how many were created."""
    synthetic_events = SyntheticEventBuilder(event_codes).build_events()
    for out_name, event_bytes in synthetic_events.items():
        (corpus_dir / out_name).write_bytes(event_bytes)
    return len(synthetic_events)


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            f"usage: {Path(sys.argv[0]).name} <repo-root> <corpus-dir> <extracted-events-dir>"
        )

    root_dir = Path(sys.argv[1])
    corpus_dir = Path(sys.argv[2])
    extracted_root = Path(sys.argv[3])

    corpus_dir.mkdir(parents=True, exist_ok=True)

    event_codes = load_event_codes(
        root_dir / "driver/ppm_events_public.h",
        set(REGULAR_EVENT_NAMES + LARGE_PAYLOAD_EVENT_NAMES),
    )

    copy_real_events(corpus_dir, extracted_root)
    synthetic_count = write_synthetic_events(corpus_dir, event_codes)

    print(f"recreated {len(REAL_EVENT_SELECTIONS) + synthetic_count} files in {corpus_dir}")


if __name__ == "__main__":
    main()
