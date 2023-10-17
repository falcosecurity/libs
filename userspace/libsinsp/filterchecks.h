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

// note(jasondellaluce): keeping this as an import entrypoint for legacy
// reasons, as all filterchecks used to be defined in this file

#include "sinsp_filtercheck.h"
#include "filtercheck_container.h"
#include "filtercheck_event.h"
#include "filtercheck_evtin.h"
#include "filtercheck_fd.h"
#include "filtercheck_fdlist.h"
#include "filtercheck_fspath.h"
#include "filtercheck_gen_event.h"
#include "filtercheck_group.h"
#include "filtercheck_k8s.h"
#include "filtercheck_mesos.h"
#include "filtercheck_rawstring.h"
#include "filtercheck_reference.h"
#include "filtercheck_syslog.h"
#include "filtercheck_thread.h"
#include "filtercheck_tracer.h"
#include "filtercheck_user.h"
#include "filtercheck_utils.h"
