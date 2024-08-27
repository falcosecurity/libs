// SPDX-License-Identifier: Apache-2.0
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

#include <libsinsp/filter/ast.h>
#include <libsinsp/events/sinsp_events.h>

namespace libsinsp {
namespace filter {
namespace ast {

/*!
    \brief Visits a filter AST and returns a set containing all the
    ppm_event_codes for which the filter expression can be evaluated as true.
    \param e The AST expression to be visited
*/
libsinsp::events::set<ppm_event_code> ppm_event_codes(const expr* e);

/*!
    \brief Visits a filter AST and returns a set containing all the
    ppm_sc_codes for which the filter expression can be evaluated as true.
    \param e The AST expression to be visited
*/
libsinsp::events::set<ppm_sc_code> ppm_sc_codes(const expr* e);

}
}
}
