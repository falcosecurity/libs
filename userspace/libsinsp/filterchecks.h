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
#include "sinsp_filtercheck_container.h"
#include "sinsp_filtercheck_event.h"
#include "sinsp_filtercheck_evtin.h"
#include "sinsp_filtercheck_fd.h"
#include "sinsp_filtercheck_fdlist.h"
#include "sinsp_filtercheck_fspath.h"
#include "sinsp_filtercheck_gen_event.h"
#include "sinsp_filtercheck_group.h"
#include "sinsp_filtercheck_k8s.h"
#include "sinsp_filtercheck_mesos.h"
#include "sinsp_filtercheck_rawstring.h"
#include "sinsp_filtercheck_reference.h"
#include "sinsp_filtercheck_syslog.h"
#include "sinsp_filtercheck_thread.h"
#include "sinsp_filtercheck_tracer.h"
#include "sinsp_filtercheck_user.h"
#include "sinsp_filtercheck_utils.h"
