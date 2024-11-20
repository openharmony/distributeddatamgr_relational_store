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

#ifndef NAPI_RDB_CONTEXT_H
#define NAPI_RDB_CONTEXT_H

#include "napi_async_call.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_predicates.h"
#include "transaction.h"
#include "values_buckets.h"

namespace OHOS {
namespace RelationalStoreJsKit {
class ResultSetProxy;
using namespace OHOS::NativeRdb;
struct RdbStoreContextBase : public ContextBase {
    std::shared_ptr<NativeRdb::RdbStore> StealRdbStore()
    {
        auto rdb = std::move(rdbStore);
        rdbStore = nullptr;
        return rdb;
    }
    std::shared_ptr<NativeRdb::RdbStore> rdbStore = nullptr;
};

struct RdbStoreContext : public RdbStoreContextBase {
    std::string device;
    std::string tableName;
    std::vector<std::string> tablesNames;
    std::string whereClause;
    std::string sql;
    RdbPredicatesProxy *predicatesProxy;
    std::vector<std::string> columns;
    ValuesBucket valuesBucket;
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBuckets sharedValuesBuckets;
    std::map<std::string, ValueObject> numberMaps;
    std::vector<ValueObject> bindArgs;
    int64_t int64Output;
    int intOutput;
    ValueObject sqlExeOutput;
    std::vector<uint8_t> newKey;
    std::shared_ptr<ResultSet> resultSet;
    std::string aliasName;
    std::string pathName;
    std::string srcName;
    std::string columnName;
    int32_t enumArg;
    int32_t distributedType;
    int32_t syncMode;
    uint64_t cursor = UINT64_MAX;
    int64_t txId = 0;
    DistributedRdb::DistributedConfig distributedConfig;
    napi_ref asyncHolder = nullptr;
    NativeRdb::ConflictResolution conflictResolution;
    DistributedRdb::SyncResult syncResult;
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;
    std::vector<NativeRdb::RdbStore::PRIKey> keys;
    std::map<RdbStore::PRIKey, RdbStore::Date> modifyTime;
    bool isQuerySql = false;
    uint32_t expiredTime = 0;

    RdbStoreContext()
        : predicatesProxy(nullptr), int64Output(0), intOutput(0), enumArg(-1),
          distributedType(DistributedRdb::DistributedTableType::DISTRIBUTED_DEVICE),
          syncMode(DistributedRdb::SyncMode::PUSH), conflictResolution(ConflictResolution::ON_CONFLICT_NONE)
    {
    }
    virtual ~RdbStoreContext()
    {
    }
};

struct CreateTransactionContext : public RdbStoreContextBase {
    AppDataMgrJsKit::JSUtils::TransactionOptions transactionOptions;
    std::shared_ptr<Transaction> transaction;
};
} // namespace RelationalStoreJsKit
} // namespace OHOS
#endif // NAPI_RDB_CONTEXT_H