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

#include <list>
#include <memory>
#include <mutex>

#include "napi_async_call.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_predicates.h"
#include "rdb_store.h"
#include "transaction.h"
#include "values_buckets.h"
#include "napi_sync_observer.h"

namespace OHOS {
namespace RelationalStoreJsKit {
class ResultSetProxy;
class NapiRdbStoreObserver;
class NapiStatisticsObserver;
class NapiPerfStatObserver;
class NapiLogObserver;
using namespace OHOS::NativeRdb;

struct NapiRdbStoreData {
    std::list<std::shared_ptr<NapiRdbStoreObserver>> observers_[DistributedRdb::SUBSCRIBE_MODE_MAX];
    std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> localObservers_;
    std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> localSharedObservers_;
    std::list<std::shared_ptr<SyncObserver>> syncObservers_;
    std::list<std::shared_ptr<NapiStatisticsObserver>> statisticses_;
    std::list<std::shared_ptr<NapiLogObserver>> logObservers_;
};

struct RdbStoreContextBase : public ContextBase {
    std::shared_ptr<NativeRdb::RdbStore> StealRdbStore();
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
    NativeRdb::RdbStoreConfig::CryptoParam cryptoParam;
    std::shared_ptr<NapiRdbStoreData> napiRdbStoreData = nullptr;

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

int ParseTransactionOptions(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<CreateTransactionContext> context);
int ParseTableName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseCursor(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseCryptoParam(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseColumnName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParsePrimaryKey(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseDevice(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseTablesName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseSyncModeArg(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseDistributedTypeArg(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<RdbStoreContext> context);

int ParseDistributedConfigArg(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<RdbStoreContext> context);

int ParseCloudSyncModeArg(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseCloudSyncCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParsePredicates(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseSrcType(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseSrcName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseColumns(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseBindArgs(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseSql(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseTxId(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseSendableValuesBucket(const napi_env env, const napi_value map, std::shared_ptr<RdbStoreContext> context);

int ParseValuesBucket(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseValuesBuckets(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

int ParseConflictResolution(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context);

std::shared_ptr<Error> ParseRdbPredicatesProxy(
    napi_env env, napi_value arg, std::shared_ptr<RdbPredicates> &predicates);

std::shared_ptr<Error> ParseSendableValuesBucket(const napi_env env, const napi_value map, ValuesBucket &valuesBucket);

std::shared_ptr<Error> ParseValuesBucket(napi_env env, napi_value arg, ValuesBucket &valuesBucket);

std::shared_ptr<Error> ParseValuesBuckets(napi_env env, napi_value arg, ValuesBuckets &valuesBuckets);

std::shared_ptr<Error> ParseConflictResolution(
    const napi_env env, const napi_value arg, NativeRdb::ConflictResolution &conflictResolution);
} // namespace RelationalStoreJsKit
} // namespace OHOS
#endif // NAPI_RDB_CONTEXT_H