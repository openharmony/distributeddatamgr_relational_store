/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_HITRACE_METER_H
#define INTERFACES_INNERKITS_NATIVE_HITRACE_METER_H

#include <mutex>
#include <string>
#include <unistd.h>

#include "hitrace_meter_c.h"

using ExecuteCallbackNapi = void (*)(void*, bool);
using DeleteCallbackNapi = void (*)(void*);
using ExecuteCallbackAni = void (*)(void*, bool);
using DeleteCallbackAni = void (*)(void*);

#ifdef __cplusplus
extern "C" {
#endif

constexpr uint64_t HITRACE_TAG_NEVER = 0;
constexpr uint64_t HITRACE_TAG_ALWAYS = (1ULL << 0);
constexpr uint64_t HITRACE_TAG_DISTRIBUTEDDATA = (1ULL << 36);

constexpr uint64_t HITRACE_TAG_LAST = (1ULL << 62);
constexpr uint64_t HITRACE_TAG_VALID_MASK = ((HITRACE_TAG_LAST - 1) | HITRACE_TAG_LAST);

#ifndef HITRACE_TAG
#define HITRACE_TAG HITRACE_TAG_NEVER
#endif

#define HITRACE_METER_NAME(TAG, str) HitraceScoped TOKENPASTE2(tracer, __LINE__)(TAG, str)
#define HITRACE_METER(TAG) HITRACE_METER_NAME(TAG, __func__)
#define HITRACE_METER_FMT(TAG, fmt, ...) HitraceMeterFmtScoped TOKENPASTE2(tracer, __LINE__)(TAG, fmt, ##__VA_ARGS__)

#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)

void UpdateTraceLabel(void);
void SetTraceDisabled(bool disable);
void StartTrace(uint64_t tag, const std::string& name, float limit = -1);
void StartTraceEx(HiTraceOutputLevel level, uint64_t tag, const char* name, const char* customArgs = "");
void FinishTrace(uint64_t tag);
void FinishTraceEx(HiTraceOutputLevel level, uint64_t tag);
void MiddleTrace(uint64_t tag, const std::string& beforeValue, const std::string& afterValue);
void CountTrace(uint64_t tag, const std::string& name, int64_t count);
void CountTraceEx(HiTraceOutputLevel level, uint64_t tag, const char* name, int64_t count);
bool IsTagEnabled(uint64_t tag);

class HitraceScoped {
public:
    inline HitraceScoped(uint64_t tag, const std::string& name) : mTag(tag)
    {
        StartTrace(mTag, name);
    }

    inline ~HitraceScoped()
    {
        FinishTrace(mTag);
    }
private:
    uint64_t mTag;
};

class HitraceScopedEx {
public:
    inline HitraceScopedEx(HiTraceOutputLevel level, uint64_t tag, const char* name,
        const char* customArgs = "") : tag_(tag), level_(level)
    {
        StartTraceEx(level_, tag_, name, customArgs);
    }

    inline ~HitraceScopedEx()
    {
        FinishTraceEx(level_, tag_);
    }
private:
    uint64_t tag_;
    HiTraceOutputLevel level_;
};

#ifdef __cplusplus
}
#endif
#endif