/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef HI_SYS_EVENT_H
#define HI_SYS_EVENT_H

namespace OHOS::HiviewDFX {

inline void HiSysEventWrite(...)
{
}

class HiSysEvent {
public:
    class Domain {
    public:
        static constexpr char DISTRIBUTED_DATAMGR[] = "DISTDATAMGR";
    };

    enum EventType {
        FAULT = 1,     // system fault event
        STATISTIC = 2, // system statistic event
        SECURITY = 3,  // system security event
        BEHAVIOR = 4   // system behavior event
    };
};
} // namespace OHOS::HiviewDFX

#endif // HI_SYS_EVENT_H
