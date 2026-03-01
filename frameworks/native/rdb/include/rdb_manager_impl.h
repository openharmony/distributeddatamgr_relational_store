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

#ifndef DISTRIBUTED_RDB_RDB_MANAGER_IMPL_H
#define DISTRIBUTED_RDB_RDB_MANAGER_IMPL_H

#include <map>
#include <memory>
#include <mutex>

#include "concurrent_map.h"
#include "irdb_service.h"
#include "iremote_object.h"
#include "rdb_manager.h"
#include "rdb_types.h"
#include "refbase.h"

namespace OHOS::DistributedRdb {
class RdbService;
class RdbStoreDataServiceProxy;
class RdbManagerImpl : public RdbManager {
public:
    static constexpr int RETRY_INTERVAL = 1;
    static constexpr int WAIT_TIME = 2;

    std::pair<int32_t, std::shared_ptr<RdbService>> GetRdbService(const RdbSyncerParam &param);

    std::string GetSelfBundleName();

    void OnRemoteDied();

private:
    class Factory {
    public:
        Factory();
        ~Factory();
    };
    RdbManagerImpl();

    ~RdbManagerImpl();

    void ResetServiceHandle();

    int32_t CleanUp();

    sptr<IRemoteObject::DeathRecipient> LinkToDeath(const sptr<IRemoteObject> &remote);

    static std::shared_ptr<RdbStoreDataServiceProxy> GetDistributedDataManager(const std::string &bundleName);

    static int32_t Clean();

    static RdbManagerImpl instance_;
    static Factory factory_;

    std::mutex mutex_;
    std::shared_ptr<RdbStoreDataServiceProxy> distributedDataMgr_;
    std::shared_ptr<RdbService> rdbService_;
    RdbSyncerParam param_;
    std::string bundleName_;
};
} // namespace OHOS::DistributedRdb
#endif
