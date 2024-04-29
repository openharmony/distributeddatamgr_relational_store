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

#ifndef NATIVE_RDB_LOCAL_DB_OBSERVER_H
#define NATIVE_RDB_LOCAL_DB_OBSERVER_H

#include <memory>
#include "rdb_types.h"
#include "store_observer.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::DistributedRdb;
class RdbStoreLocalDbObserver : public DistributedDB::StoreObserver {
public:
    explicit RdbStoreLocalDbObserver(const std::shared_ptr<RdbStoreObserver> &observer) : observer_(observer) {};
    virtual ~RdbStoreLocalDbObserver() {};
    void OnChange(DistributedDB::StoreObserver::StoreChangedInfo &&data) override;
    std::shared_ptr<RdbStoreObserver> GetObserver()
    {
        return observer_;
    }

private:
    void Convert(const DistributedDB::ChangedData &dataInfo, RdbStoreObserver::ChangeInfo &changeInfo,
        RdbStoreObserver::ChangeType changeType);
    std::shared_ptr<RdbStoreObserver> observer_ = nullptr;
};
} // namespace NativeRdb
} // namespace OHOS
#endif