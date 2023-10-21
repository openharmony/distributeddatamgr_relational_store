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

#ifndef DISTRIBUTED_RDB_RDB_NOTIFIER_H
#define DISTRIBUTED_RDB_RDB_NOTIFIER_H
#include "rdb_types.h"
#include "distributeddata_relational_store_ipc_interface_code.h"
namespace OHOS::DistributedRdb {
class IRdbNotifier {
public:
    using ChangeInfo = RdbStoreObserver::ChangeInfo;
    using PrimaryFields = std::map<std::string, std::string>;
    virtual int32_t OnComplete(uint32_t seqNum, Details &&result) = 0;
    virtual int32_t OnComplete(const std::string& storeName, Details &&result) = 0;

    virtual int32_t OnChange(const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo) = 0;
};
} // namespace OHOS::DistributedRdb
#endif
