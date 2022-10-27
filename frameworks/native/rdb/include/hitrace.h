/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DISTRIBUTEDDATAMGR_NATIVERDB_HITRACE_H
#define DISTRIBUTEDDATAMGR_NATIVERDB_HITRACE_H

#include <string>

#include "hitrace_meter.h"

namespace OHOS {
namespace NativeRdb {
class HiTrace final {
public:
    inline HiTrace(const std::string &value)
    {
        StartTrace(HITRACE_TAG_DISTRIBUTEDDATA, value);
    }

    inline ~HiTrace()
    {
        FinishTrace(HITRACE_TAG_DISTRIBUTEDDATA);
    }
};
} // namespace NativeRdb
} // namespace OHOS

#endif