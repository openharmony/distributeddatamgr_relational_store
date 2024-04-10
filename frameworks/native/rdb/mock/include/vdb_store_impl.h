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
#include <thread>

#include "concurrent_map.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"

namespace OHOS::NativeRdb {

class RdbConnectionPool {
public:
    explicit RdbConnectionPool(const RdbStoreConfig &storeConfig);
    virtual ~RdbConnectionPool();
};

class VdbStoreImpl : public RdbStoreImpl, public std::enable_shared_from_this<VdbStoreImpl> {
public:
    VdbStoreImpl(const RdbStoreConfig &config, int &errCode) : RdbStoreImpl(config, errCode)
    {
    }

    ~VdbStoreImpl() override
    {
    }

    // Interface to support in VDB
    std::pair<int, int64_t> BeginTrans() override
    {
        return {};
    }

    int Commit(int64_t trxId) override
    {
        return 0;
    }

    int RollBack(int64_t trxId) override
    {
        return 0;
    }

    std::pair<int32_t, ValueObject> Execute(const std::string &sql,
        const std::vector<ValueObject> &bindArgs, int64_t trxId) override
    {
        return {};
    }

    int ExecuteSqlByTrxId(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = {}, int64_t trxId = 0)
    {
        return 0;
    }

    // Interface not to support in VDB
    int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) override
    {
        return 0;
    }

    int BatchInsert(int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values) override
    {
        return 0;
    }

    int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override
    {
        return 0;
    }

    int InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution) override
    {
        return 0;
    }

    int Update(int &changedRows, const std::string &table, const ValuesBucket &values, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override
    {
        return 0;
    }

    int Update(int &changedRows, const std::string &table, const ValuesBucket &values, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override
    {
        return 0;
    }

    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution) override
    {
        return 0;
    }

    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution) override
    {
        return 0;
    }

    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override
    {
        return 0;
    }

    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override
    {
        return 0;
    }

    int ExecuteSql(const std::string& sql, const std::vector<ValueObject>& bindArgs) override
    {
        return 0;
    }

    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override
    {
        return 0;
    }

    int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override
    {
        return 0;
    }

    int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override
    {
        return 0;
    }

    int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override
    {
        return 0;
    }

    int Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey) override
    {
        return 0;
    }

    int GetVersion(int &version) override
    {
        return 0;
    }

    int SetVersion(int version) override
    {
        return 0;
    }

    int BeginTransaction() override
    {
        return 0;
    }

    int RollBack() override
    {
        return 0;
    }

    int Commit() override
    {
        return 0;
    }

    bool IsInTransaction() override
    {
        return 0;
    }

    int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey) override
    {
        return 0;
    }

    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override
    {
        return nullptr;
    }

    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const std::vector<ValueObject> &args) override
    {
        return nullptr;
    }

    std::shared_ptr<ResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override
    {
        return nullptr;
    }

    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override
    {
        return 0;
    }

    int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override
    {
        return 0;
    }

    int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override
    {
        return 0;
    }

    std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) override
    {
        return {};
    }

    std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2) override
    {
        return {};
    }

private:
    std::shared_ptr<RdbConnectionPool> rdConnectionPool_ = nullptr;
};
} // namespace OHOS::NativeRdb
#endif
