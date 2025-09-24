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

#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

#include <mutex>
#include <memory>
#include "concurrent_map.h"
#include "rdb_store.h"
#include "rdb_types.h"

namespace OHOS {
namespace NativeRdb {

class HandleManager {
public:
    API_EXPORT static HandleManager &GetInstance();
    ~HandleManager() = default;

    API_EXPORT int Register(const RdbStoreConfig &rdbStoreConfig, std::shared_ptr<CorruptHandler> corruptHandler);
    API_EXPORT int Unregister(const RdbStoreConfig &rdbStoreConfig);
    std::shared_ptr<CorruptHandler> GetHandler(const std::string &path);
    static void HandleCorrupt(const RdbStoreConfig &config);

private:
    HandleManager() = default;
    HandleManager(const HandleManager &) = delete;
    HandleManager &operator=(const HandleManager &) = delete;
    ConcurrentMap<std::string, std::shared_ptr<CorruptHandler>> handlers_;
    std::mutex mutex_;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // HANDLE_MANAGER_H