/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RELATIONAL_STORE_IMPL_H
#define RELATIONAL_STORE_IMPL_H

#include <list>
#include <memory>

#include "oh_predicates.h"
#include "rdb_store.h"
#include "relational_store.h"

namespace OHOS {
namespace RdbNdk {
class NDKDetailProgressObserver : public DistributedRdb::DetailProgressObserver {
public:
    explicit NDKDetailProgressObserver(const Rdb_ProgressObserver *callback);
    void ProgressNotification(const DistributedRdb::Details &details);
    bool operator==(const Rdb_ProgressObserver *callback);

private:
    const Rdb_ProgressObserver *callback_;
};

class NDKStoreObserver : public OHOS::DistributedRdb::RdbStoreObserver {
public:
    using Origin = DistributedRdb::Origin;
    using RdbStoreObserver = OHOS::DistributedRdb::RdbStoreObserver;

    NDKStoreObserver(const Rdb_DataObserver *observer, int mode);
    ~NDKStoreObserver() noexcept override = default;

    void OnChange(const std::vector<std::string> &devices) override;

    void OnChange(const OHOS::DistributedRdb::Origin &origin, const PrimaryFields &fields,
        ChangeInfo &&changeInfo) override;

    void OnChange() override;
    bool operator==(const Rdb_DataObserver *other);

private:
    void ConvertKeyInfoData(Rdb_KeyInfo::Rdb_KeyData *keyInfoData,
        std::vector<RdbStoreObserver::PrimaryKey> &primaryKey);
    size_t GetKeyInfoSize(RdbStoreObserver::ChangeInfo &&changeInfo);
    int32_t GetKeyDataType(std::vector<RdbStoreObserver::PrimaryKey> &primaryKey);
    int mode_ = Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD;
    const Rdb_DataObserver *observer_;
};

class RelationalStore : public OH_Rdb_Store {
public:
    explicit RelationalStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> store);
    ~RelationalStore();
    std::shared_ptr<OHOS::NativeRdb::RdbStore> GetStore()
    {
        return store_;
    }
    int SubscribeAutoSyncProgress(const Rdb_ProgressObserver *callback);
    int UnsubscribeAutoSyncProgress(const Rdb_ProgressObserver *callback);
    int DoSubScribe(Rdb_SubscribeType type, const Rdb_DataObserver *observer);
    int DoUnsubScribe(Rdb_SubscribeType type, const Rdb_DataObserver *observer);

private:
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store_;
    std::mutex mutex_;
    std::list<std::shared_ptr<NDKDetailProgressObserver>> callbacks_;
    std::map<Rdb_SubscribeType, std::vector<std::shared_ptr<NDKStoreObserver>>> dataObservers_;
};

class NDKUtils {
public:
    static OHOS::DistributedRdb::SyncMode TransformMode(Rdb_SyncMode &mode);
    static OHOS::DistributedRdb::SubscribeMode GetSubscribeType(Rdb_SubscribeType &type);
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_STORE_IMPL_H
