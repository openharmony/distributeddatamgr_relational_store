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
#include "iremote_proxy.h"
#include "rdb_types.h"
#include "refbase.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS::DistributedRdb {
class RdbService;
class RdbServiceProxy;
class RdbStoreDataServiceProxy;
class RdbManagerImpl {
public:
    static constexpr int RETRY_INTERVAL = 1;
    static constexpr int WAIT_TIME = 2;

    static RdbManagerImpl &GetInstance();

    std::pair<int32_t, std::shared_ptr<RdbService>> GetRdbService(const RdbSyncerParam &param);

    std::string GetSelfBundleName();

    void OnRemoteDied();

    class ServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ServiceDeathRecipient(RdbManagerImpl* owner) : owner_(owner) {}
        void OnRemoteDied(const wptr<IRemoteObject> &object) override
        {
            if (owner_ != nullptr) {
                owner_->OnRemoteDied();
            }
        }

    private:
        RdbManagerImpl *owner_;
    };

    class ServiceProxyLoadCallback : public SystemAbilityLoadCallbackStub {
    public:
        ServiceProxyLoadCallback() = default;
        virtual ~ServiceProxyLoadCallback() = default;

        void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject) override;
        void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;
    };

private:
    RdbManagerImpl();

    ~RdbManagerImpl();

    void ResetServiceHandle();

    int32_t CleanUp();

    static sptr<IRemoteObject::DeathRecipient> LinkToDeath(const sptr<IRemoteObject> &remote);

    static std::shared_ptr<RdbStoreDataServiceProxy> GetDistributedDataManager(const std::string &bundleName);

    std::mutex mutex_;
    std::shared_ptr<RdbStoreDataServiceProxy> distributedDataMgr_;
    std::shared_ptr<RdbService> rdbService_;
    RdbSyncerParam param_;
    std::string bundleName_;
};

class RdbStoreDataServiceProxy : public IRemoteProxy<DistributedRdb::IKvStoreDataService> {
public:
    explicit RdbStoreDataServiceProxy(const sptr<IRemoteObject> &impl);
    ~RdbStoreDataServiceProxy() = default;
    sptr<IRemoteObject> GetFeatureInterface(const std::string &name) override;
    int32_t RegisterDeathObserver(const std::string &bundleName, sptr<IRemoteObject> observer,
        const std::string &featureName = DistributedRdb::RdbService::SERVICE_NAME) override;
    int32_t Exit(const std::string &featureName = DistributedRdb::RdbService::SERVICE_NAME) override;
    std::pair<int32_t, std::string> GetSelfBundleName() override;
private:
    sptr<IRemoteObject> clientDeathObserver_;
};
} // namespace OHOS::DistributedRdb
#endif
