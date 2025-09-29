/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CORRUPTED_HANDLE_MANAGER_H
#define CORRUPTED_HANDLE_MANAGER_H

#include <memory>
#include "concurrent_map.h"
#include "rdb_store.h"
#include "rdb_types.h"

namespace OHOS {
namespace NativeRdb {

class CorruptedHandleManager {
public:
    API_EXPORT static CorruptedHandleManager &GetInstance();
    ~CorruptedHandleManager() = default;

    API_EXPORT int Register(const RdbStoreConfig &config, std::shared_ptr<CorruptHandler> corruptHandler);
    API_EXPORT int Unregister(const RdbStoreConfig &config);
    std::shared_ptr<CorruptHandler> GetHandler(const RdbStoreConfig &config);
    void HandleCorrupt(const RdbStoreConfig &config);
    void PauseCallback();
    void ResumeCallback();

private:
    CorruptedHandleManager() = default;
    CorruptedHandleManager(const CorruptedHandleManager &) = delete;
    CorruptedHandleManager &operator=(const CorruptedHandleManager &) = delete;
    ConcurrentMap<std::string, std::shared_ptr<CorruptHandler>> handlers_;
    ConcurrentMap<uint64_t, int> pausedPaths_;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // HANDLE_MANAGER_H