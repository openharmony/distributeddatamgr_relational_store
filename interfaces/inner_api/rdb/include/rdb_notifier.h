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
namespace OHOS::DistributedRdb {
class IRdbNotifier {
public:
    using ChangeInfo = RdbStoreObserver::ChangeInfo;
    using PrimaryFields = std::map<std::string, std::string>;
    enum Code : int32_t {
        RDB_NOTIFIER_CMD_SYNC_COMPLETE,
        RDB_NOTIFIER_CMD_DATA_CHANGE,
        RDB_NOTIFIER_CMD_DATA_DETAILS,
        RDB_NOTIFIER_CMD_MAX
    };
    virtual int32_t OnComplete(uint32_t seqNum, Details &&result) = 0;

    virtual int32_t OnChange(const std::string &storeName, const std::vector<std::string> &devices) = 0;
};
} // namespace OHOS::DistributedRdb
#endif
