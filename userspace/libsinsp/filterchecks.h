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
#include "filter/checks/event.h"
#include "filter/checks/evtin.h"
#include "filter/checks/fd.h"
#include "filter/checks/fdlist.h"
#include "filter/checks/fspath.h"
#include "filter/checks/gen_event.h"
#include "filter/checks/group.h"
#include "filter/checks/k8s.h"
#include "filter/checks/mesos.h"
#include "filter/checks/rawstring.h"
#include "filter/checks/reference.h"
#include "filter/checks/syslog.h"
#include "filter/checks/thread.h"
#include "filter/checks/tracer.h"
#include "filter/checks/user.h"
#include "filter/checks/utils.h"
