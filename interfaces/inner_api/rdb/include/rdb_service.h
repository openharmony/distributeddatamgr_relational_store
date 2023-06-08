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

#ifndef DISTRIBUTED_RDB_RDB_SERVICE_H
#define DISTRIBUTED_RDB_RDB_SERVICE_H

#include <memory>
#include <string>
#include "rdb_types.h"
#include "rdb_notifier.h"

namespace OHOS {
template <typename T>
class sptr;
class IRemoteObject;
namespace DistributedRdb {
class RdbService {
public:
    enum {
        RDB_SERVICE_CMD_OBTAIN_TABLE,
        RDB_SERVICE_CMD_INIT_NOTIFIER,
        RDB_SERVICE_CMD_SET_DIST_TABLE,
        RDB_SERVICE_CMD_SYNC,
        RDB_SERVICE_CMD_ASYNC,
        RDB_SERVICE_CMD_SUBSCRIBE,
        RDB_SERVICE_CMD_UNSUBSCRIBE,
        RDB_SERVICE_CMD_REMOTE_QUERY,
        RDB_SERVICE_CMD_GET_SCHEMA,
        RDB_SERVICE_CMD_MAX
    };

    struct Option {
        int32_t mode;
        uint32_t seqNum = 0;
        bool isAsync = false;
    };

    virtual std::string ObtainDistributedTableName(const std::string &device, const std::string &table) = 0;

    virtual int32_t SetDistributedTables(
        const RdbSyncerParam &param, const std::vector<std::string> &tables, int32_t type = DISTRIBUTED_DEVICE) = 0;

    virtual int32_t Sync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
        const AsyncDetail &async) = 0;

    virtual int32_t Subscribe(const RdbSyncerParam &param, const SubscribeOption &option,
        RdbStoreObserver *observer) = 0;

    virtual int32_t UnSubscribe(const RdbSyncerParam &param, const SubscribeOption &option,
        RdbStoreObserver *observer) = 0;

    virtual int32_t RemoteQuery(const RdbSyncerParam &param, const std::string &device, const std::string &sql,
        const std::vector<std::string> &selectionArgs, sptr<IRemoteObject> &resultSet) = 0;

    virtual int32_t InitNotifier(const RdbSyncerParam &param, sptr<IRemoteObject> notifier) = 0;

    virtual int32_t GetSchema(const RdbSyncerParam &param) = 0;

    inline static constexpr const char *SERVICE_NAME = "relational_store";
};
}
} // namespace OHOS::DistributedRdb
#endif
