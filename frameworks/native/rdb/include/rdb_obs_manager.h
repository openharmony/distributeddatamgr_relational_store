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
#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_OBS_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_OBS_MANAGER_H
#include <list>
#include <memory>
#include <string>

#include "concurrent_map.h"
#include "rdb_types.h"

namespace OHOS::NativeRdb {
class RdbObsManager {
public:
    RdbObsManager() = default;
    virtual ~RdbObsManager();
    int32_t Register(const std::string &uri, std::shared_ptr<DistributedRdb::RdbStoreObserver> rdbStoreObserver);
    int32_t Unregister(const std::string &uri, std::shared_ptr<DistributedRdb::RdbStoreObserver> rdbStoreObserver);
    int32_t Notify(const std::string &uri);

private:
    using RegisterFunc = int32_t (*)(const std::string &, std::shared_ptr<DistributedRdb::RdbStoreObserver>);
    using UnregisterFunc = int32_t (*)(const std::string &, std::shared_ptr<DistributedRdb::RdbStoreObserver>);
    using NotifyFunc = int32_t (*)(const std::string &);
    using CleanFunc = bool (*)();
    struct ObsAPIInfo {
        RegisterFunc registerFunc = nullptr;
        UnregisterFunc unregisterFunc = nullptr;
        NotifyFunc notifyFunc = nullptr;
        CleanFunc cleanFunc = nullptr;
    };
    static ObsAPIInfo GetApiInfo();
    static int32_t CleanUp();
    static std::mutex mutex_;
    static ObsAPIInfo apiInfo_;
    static void *handle_;
    ConcurrentMap<std::string, std::list<std::shared_ptr<DistributedRdb::RdbStoreObserver>>> obs_;
};
} // namespace OHOS::NativeRdb
#endif //OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_OBS_MANAGER_H
