/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef DISTRIBUTEDDATAMGR_NAPI_RDB_TRACE_H
#define DISTRIBUTEDDATAMGR_NAPI_RDB_TRACE_H

#define DO_NOTHING

#ifdef WINDOWS_PLATFORM
#define DISTRIBUTED_DATA_HITRACE(trace) DO_NOTHING

#elif MAC_PLATFORM
#define DISTRIBUTED_DATA_HITRACE(trace) DO_NOTHING

#else
#include "napi_hitrace.h"
#define DISTRIBUTED_DATA_HITRACE(trace) HiTrace hitrace(trace)

#endif

#endif