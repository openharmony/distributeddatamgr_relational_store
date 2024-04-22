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

#define LOG_TAG "RdbLocalDbObserver"
#include "rdb_local_db_observer.h"

#include "raw_data_parser.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::DistributedRdb;

void RdbStoreLocalDbObserver::OnChange(DistributedDB::StoreObserver::StoreChangedInfo &&data)
{
    RdbStoreObserver::ChangeInfo changeInfo;
    for (const auto &dataInfo : data) {
        Convert(dataInfo, changeInfo, RdbStoreObserver::ChangeType::CHG_TYPE_INSERT);
        Convert(dataInfo, changeInfo, RdbStoreObserver::ChangeType::CHG_TYPE_UPDATE);
        Convert(dataInfo, changeInfo, RdbStoreObserver::ChangeType::CHG_TYPE_DELETE);
    }
    Origin origin;
    RdbStoreObserver::PrimaryFields fields;
    observer_->OnChange(origin, fields, std::move(changeInfo));
}

void RdbStoreLocalDbObserver::Convert(const DistributedDB::ChangedData &dataInfo,
    RdbStoreObserver::ChangeInfo &changeInfo, RdbStoreObserver::ChangeType changeType)
{
    if (changeType < RdbStoreObserver::ChangeType::CHG_TYPE_INSERT ||
        changeType >= RdbStoreObserver::ChangeType::CHG_TYPE_BUTT) {
        return;
    }
    changeInfo.try_emplace(dataInfo.tableName);
    for (const auto &primary : dataInfo.primaryData[changeType]) {
        RdbStoreObserver::PrimaryKey primaryKey;
        RawDataParser::Convert(std::move(primary[0]), primaryKey);
        changeInfo[dataInfo.tableName][changeType].push_back(std::move(primaryKey));
    }
}

} // namespace NativeRdb
} // namespace OHOS