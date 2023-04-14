/*
Copyright (C) 2023 The Falco Authors.

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

namespace scap_gvisor {
namespace stats {
    enum gvisor_counters_stats {
        GVISOR_N_EVTS = 0,
        GVISOR_N_DROPS_BUG,
        GVISOR_N_DROPS_BUFFER_TOTAL,
        GVISOR_N_DROPS,
        MAX_GVISOR_COUNTERS_STATS
    };

} // namespace stats
} // namespace scap_gvisor
