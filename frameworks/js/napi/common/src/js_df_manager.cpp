/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "js_df_manager.h"

#include <unistd.h>

#include <mutex>

namespace OHOS::AppDataMgrJsKit {
JSDFManager &JSDFManager::GetInstance()
{
    static JSDFManager instance;
    return instance;
}

void JSDFManager::AddNewInfo(void *data)
{
    std::lock_guard<std::mutex> lockGuard(mapMutex);
    instances_[data] = 0;
}

int32_t JSDFManager::GetFreedTid(void *data)
{
    std::lock_guard<std::mutex> lockGuard(mapMutex);
    int32_t freedTid = 0;
    auto it = instances_.find(data);
    if (it != instances_.end()) {
        auto tid = it->second;
        if (tid != 0) {
            freedTid = tid;
        } else {
#if defined(CROSS_PLATFORM)
            tid = 0;
#else
            tid = gettid();
#endif
            instances_[data] = tid;
        }
    }
    return freedTid;
}
} // namespace OHOS::AppDataMgrJsKit