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
#include "result_set.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS::NativeRdb {
enum class ConflictResolution {
    ON_CONFLICT_NONE = 0,
    ON_CONFLICT_ROLLBACK,
    ON_CONFLICT_ABORT,
    ON_CONFLICT_FAIL,
    ON_CONFLICT_IGNORE,
    ON_CONFLICT_REPLACE,
};

class RdbStore {
public:
    virtual ~RdbStore() {}
#ifdef WINDOWS_PLATFORM
    virtual void Clear();
#endif
    virtual int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) = 0;
    virtual int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<ValuesBucket> &initialBatchValues) = 0;
    virtual int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) = 0;
    virtual int InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
        const ValuesBucket &initialValues,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause = "",
        const std::vector<std::string> &whereArgs = std::vector<std::string>()) = 0;
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause = "", const std::vector<std::string> &whereArgs = std::vector<std::string>(),
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause = "",
        const std::vector<std::string> &whereArgs = std::vector<std::string>()) = 0;
    virtual std::unique_ptr<ResultSet> QueryByStep(
        const std::string &sql, const std::vector<std::string> &selectionArgs = std::vector<std::string>()) = 0;
    virtual int ExecuteSql(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>()) = 0;
    virtual int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>()) = 0;
    virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>()) = 0;
    virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>()) = 0;
    virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>()) = 0;
    virtual int Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey) = 0;
    virtual int Attach(
        const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey) = 0;

    virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates) = 0;
    virtual std::unique_ptr<ResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> columns) = 0;
    virtual int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) = 0;
    virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates) = 0;

    virtual int GetRdbStatus() = 0;
    virtual void SetRdbStatus(int status) = 0;
    virtual int GetVersion(int &version) = 0;
    virtual int SetVersion(int version) = 0;
    virtual int BeginTransaction() = 0;
    virtual int RollBack() = 0;
    virtual int Commit() = 0;
    virtual bool IsInTransaction() = 0;
    virtual std::string GetPath() = 0;
    virtual bool IsHoldingConnection() = 0;
    virtual bool IsOpen() const = 0;
    virtual bool IsReadOnly() const = 0;
    virtual bool IsMemoryRdb() const = 0;
    virtual int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey) = 0;
    virtual int ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
        const std::vector<uint8_t> &newKey) = 0;
};
} // namespace OHOS::NativeRdb
#endif
