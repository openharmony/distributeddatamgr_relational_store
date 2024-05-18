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

#ifndef NATIVE_RDB_RDB_STORE_H
#define NATIVE_RDB_RDB_STORE_H

#include <memory>
#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "result_set.h"
#include "value_object.h"
#include "values_bucket.h"
namespace OHOS::NativeRdb {
class RdbStore {
public:
    using RdbStoreObserver = DistributedRdb::RdbStoreObserver;
    using PRIKey = RdbStoreObserver::PrimaryKey;
    using Date = DistributedRdb::Date;

    virtual ~RdbStore() {}
    virtual int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) = 0;
    virtual int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<ValuesBucket> &values) = 0;
    virtual int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &values) = 0;
    virtual int InsertWithConflictResolution(
        int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs) = 0;
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs) = 0;
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution)  = 0;
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution) = 0;
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) = 0;
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) = 0;
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &sqlArgs) = 0;
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const std::vector<ValueObject> &args) = 0;
    virtual std::shared_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) = 0;
    virtual int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = {}) = 0;
    virtual std::pair<int32_t, ValueObject> Execute(const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}, int64_t txId = 0) = 0;
    virtual int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;
    virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;
    virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;
    virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;
    virtual int Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey = {}) = 0;
    virtual int Attach(
        const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey)
    {
        return E_OK;
    }

    virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates) = 0;
    virtual std::shared_ptr<ResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) = 0;
    virtual int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) = 0;
    virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates) = 0;

    virtual int GetVersion(int &version) = 0;
    virtual int SetVersion(int version) = 0;
    virtual int BeginTransaction() = 0;
    virtual std::pair<int, int64_t> BeginTrans() = 0;
    virtual int RollBack() = 0;
    virtual int RollBack(int64_t trxId) = 0;
    virtual int Commit() = 0;
    virtual int Commit(int64_t trxId) = 0;
    virtual bool IsInTransaction() = 0;
    virtual std::string GetPath() = 0;
    virtual bool IsHoldingConnection() = 0;
    virtual bool IsOpen() const = 0;
    virtual bool IsReadOnly() const = 0;
    virtual bool IsMemoryRdb() const = 0;
    virtual int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey = {}) = 0;
    virtual std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) = 0;
    virtual std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2) = 0;
    virtual int GetRebuilt(RebuiltType &rebuilt) = 0;
};
} // namespace OHOS::NativeRdb
#endif
