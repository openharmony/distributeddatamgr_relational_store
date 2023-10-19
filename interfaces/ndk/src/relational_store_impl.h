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
class NDKStoreObserver : public OHOS::DistributedRdb::RdbStoreObserver {
public:
    using Origin = DistributedRdb::Origin;
    using RdbStoreObserver = OHOS::DistributedRdb::RdbStoreObserver;
    struct NDKChangeInfo {
        NDKChangeInfo(const Origin &origin, ChangeInfo::iterator info);
        std::string table;
        int32_t type; //datachange or asset change
        std::vector<PrimaryKey> inserted;
        std::vector<PrimaryKey> updated;
        std::vector<PrimaryKey> deleted;
    };
    explicit NDKStoreObserver(OH_Rdb_Store *store, Rdb_DataObserver *callback, int mode);
    ~NDKStoreObserver() noexcept override = default;

    void OnChange(const std::vector<std::string> &devices) override;

    void OnChange(const OHOS::DistributedRdb::Origin &origin, const PrimaryFields &fields,
        ChangeInfo &&changeInfo) override;

    void OnChange() override;

    static OHOS::DistributedRdb::SyncMode TransformMode(Rdb_SyncMode &mode);

private:
    static void TransformData(Rdb_KeyInfo &keyInfo, std::vector<RdbStoreObserver::PrimaryKey> &primaryKey);
    OH_Rdb_Store *store_;
    int mode_ = Rdb_SubscribeType::RDB_SUBSCRIBE_TYPE_CLOUD;
    Rdb_DataObserver *observer_;
};

class RelationalStore : public OH_Rdb_Store {
public:
    explicit RelationalStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> store);
    std::shared_ptr<OHOS::NativeRdb::RdbStore> GetStore()
    {
        return store_;
    }

    static OHOS::DistributedRdb::SubscribeMode GetSubscribeType(Rdb_SubscribeType &type);
private:
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_STORE_IMPL_H
