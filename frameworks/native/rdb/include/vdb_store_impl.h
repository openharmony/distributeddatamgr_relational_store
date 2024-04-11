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

#ifndef NATIVE_RDB_VDB_STORE_IMPL_H
#define NATIVE_RDB_VDB_STORE_IMPL_H

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "concurrent_map.h"
#include "data_ability_observer_stub.h"
#include "dataobs_mgr_client.h"
#include "rdb_connection_pool.h"
#include "rdb_errno.h"
#include "rdb_service.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "refbase.h"

namespace OHOS::NativeRdb {

class VdbStoreImpl : public RdbStoreImpl {
public:
    VdbStoreImpl(const RdbStoreConfig &config, int &errCode);
    ~VdbStoreImpl() override;
    // Interface to support in VDB
    std::pair<int, int64_t> BeginTrans() override;
    int Commit(int64_t trxId) override;
    int RollBack(int64_t trxId) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql,
        const std::vector<ValueObject> &bindArgs, int64_t trxId) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteSqlByTrxId(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = {}, int64_t trxId = 0);
    // Interface not to support in VDB
    int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) override;
    int BatchInsert(int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values) override;
    int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    int InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution) override;
    int Update(int &changedRows, const std::string &table, const ValuesBucket &values, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    int Update(int &changedRows, const std::string &table, const ValuesBucket &values, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override;
    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution) override;
    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution) override;
    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override;
    std::shared_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct,
        const std::string &table, const std::vector<std::string> &columns,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs, const std::string &groupBy,
        const std::string &indexName, const std::string &orderBy, const int &limit, const int &offset) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override;
    int ExecuteSql(const std::string& sql, const std::vector<ValueObject>& bindArgs) override;
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey) override;
    int GetVersion(int &version) override;
    int SetVersion(int version) override;
    int BeginTransaction() override;
    int RollBack() override;
    int Commit() override;
    bool IsInTransaction() override;
    int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const std::vector<ValueObject> &args) override;
    std::shared_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    std::shared_ptr<AbsSharedResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override;
    int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override;
    std::shared_ptr<ResultSet> RemoteQuery(const std::string &device, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, int &errCode) override;
    int SetDistributedTables(const std::vector<std::string> &tables, int32_t type,
        const DistributedRdb::DistributedConfig &distributedConfig) override;
    std::string ObtainDistributedTableName(const std::string& device, const std::string& table, int &errCode) override;
    int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async) override;
    int Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async) override;
    int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async) override;
    int Subscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;
    int UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;
    int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;
    int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;
    int Notify(const std::string &event) override;
    ModifyTime GetModifyTime(const std::string& table, const std::string& columnName,
        std::vector<PRIKey>& keys) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) override;
    std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2) override;
private:
    std::shared_ptr<RdbConnectionPool> rdConnectionPool_ = nullptr;
};
} // namespace OHOS::NativeRdb
#endif
