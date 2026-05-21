/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "relational_store_utils.h"
#include "rdb_store.h"
#include "rdb_errno.h"
#include "native_log.h"
#include "relational_store_impl_rdbstore.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
RdbStoreImpl::RdbStoreImpl(std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore)
{
    rdbStore_ = rdbStore;
}

OHOS::FFI::RuntimeType* RdbStoreImpl::GetClassType()
{
    static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("RdbStoreImpl");
    return &runtimeType;
}

NativeRdb::ValuesBucket ConvertFromValueBucket(ValuesBucket valuesBucket)
{
    int64_t mapSize = valuesBucket.size;
    NativeRdb::ValuesBucket nativeValuesBucket = NativeRdb::ValuesBucket();

    for (int64_t i = 0; i < mapSize; i++) {
        NativeRdb::ValueObject valueObject = ValueTypeToValueObject(valuesBucket.value[i]);
        std::string keyStr = valuesBucket.key[i];
        nativeValuesBucket.Put(keyStr, valueObject);
    }
    return nativeValuesBucket;
}

NativeRdb::ValuesBucket ConvertFromValueBucketEx(ValuesBucketEx valuesBucket)
{
    int64_t mapSize = valuesBucket.size;
    NativeRdb::ValuesBucket nativeValuesBucket = NativeRdb::ValuesBucket();

    for (int64_t i = 0; i < mapSize; i++) {
        NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(valuesBucket.value[i]);
        std::string keyStr = valuesBucket.key[i];
        nativeValuesBucket.Put(keyStr, valueObject);
    }
    return nativeValuesBucket;
}

std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::Query(RdbPredicatesImpl &predicates, char **column,
    int64_t columnSize)
{
    std::vector<std::string> columnsVector = std::vector<std::string>();
    for (int64_t i = 0; i < columnSize; i++) {
        columnsVector.push_back(std::string(column[i]));
    }
    auto resultSet = rdbStore_->Query(*(predicates.GetPredicates()), columnsVector);
    return resultSet;
}

std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::RemoteQuery(char *device, RdbPredicatesImpl &predicates,
    char **column, int64_t columnSize)
{
    std::vector<std::string> columnsVector;
    for (int64_t i = 0; i < columnSize; i++) {
        columnsVector.push_back(std::string(column[i]));
    }
    int32_t errCode;
    auto resultSet = rdbStore_->RemoteQuery(std::string(device), *(predicates.GetPredicates()), columnsVector,
        errCode);
    return resultSet;
}

int32_t RdbStoreImpl::Update(ValuesBucket valuesBucket, RdbPredicatesImpl &predicates,
    NativeRdb::ConflictResolution conflictResolution, int32_t *errCode)
{
    int32_t affectedRows;
    NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucket(valuesBucket);
    *errCode = rdbStore_->UpdateWithConflictResolution(affectedRows, predicates.GetPredicates()->GetTableName(),
        nativeValuesBucket, predicates.GetPredicates()->GetWhereClause(), predicates.GetPredicates()->GetBindArgs(),
        conflictResolution);
    return affectedRows;
}

int32_t RdbStoreImpl::UpdateEx(ValuesBucketEx valuesBucket, RdbPredicatesImpl &predicates,
    NativeRdb::ConflictResolution conflictResolution, int32_t *errCode)
{
    int32_t affectedRows;
    NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucketEx(valuesBucket);
    *errCode = rdbStore_->UpdateWithConflictResolution(affectedRows, predicates.GetPredicates()->GetTableName(),
        nativeValuesBucket, predicates.GetPredicates()->GetWhereClause(), predicates.GetPredicates()->GetBindArgs(),
        conflictResolution);
    return affectedRows;
}

int RdbStoreImpl::Delete(RdbPredicatesImpl &predicates, int32_t *errCode)
{
    int deletedRows = 0;
    *errCode = rdbStore_->Delete(deletedRows, *(predicates.GetPredicates()));
    return deletedRows;
}

int32_t RdbStoreImpl::SetDistributedTables(char **tables, int64_t tablesSize)
{
    std::vector<std::string> tablesVector;
    for (int64_t i = 0; i < tablesSize; i++) {
        tablesVector.push_back(std::string(tables[i]));
    }
    return rdbStore_->SetDistributedTables(tablesVector, DistributedRdb::DISTRIBUTED_DEVICE,
        DistributedRdb::DistributedConfig{false});
}

int32_t RdbStoreImpl::SetDistributedTables(char **tables, int64_t tablesSize, int32_t type)
{
    std::vector<std::string> tablesVector;
    for (int64_t i = 0; i < tablesSize; i++) {
        tablesVector.push_back(std::string(tables[i]));
    }
    return rdbStore_->SetDistributedTables(tablesVector, type, DistributedRdb::DistributedConfig{false});
}

int32_t RdbStoreImpl::SetDistributedTables(char **tables, int64_t tablesSize, int32_t type,
    DistributedRdb::DistributedConfig &distributedConfig)
{
    std::vector<std::string> tablesVector;
    for (int64_t i = 0; i < tablesSize; i++) {
        tablesVector.push_back(std::string(tables[i]));
    }
    return rdbStore_->SetDistributedTables(tablesVector, type, distributedConfig);
}

int32_t RdbStoreImpl::RollBack()
{
    return rdbStore_->RollBack();
}

int32_t RdbStoreImpl::Commit()
{
    return rdbStore_->Commit();
}

int32_t RdbStoreImpl::Commit(int64_t txId)
{
    return rdbStore_->Commit(txId);
}

int32_t RdbStoreImpl::BeginTransaction()
{
    return rdbStore_->BeginTransaction();
}

int32_t RdbStoreImpl::Backup(const char *destName)
{
    return rdbStore_->Backup(destName, newKey);
}

int32_t RdbStoreImpl::Restore(const char *srcName)
{
    return rdbStore_->Restore(srcName, newKey);
}

char *RdbStoreImpl::ObtainDistributedTableName(const char *device, const char *table)
{
    int errCode = RelationalStoreJsKit::E_INNER_ERROR;
    std::string tableName = rdbStore_->ObtainDistributedTableName(device, table, errCode);
    return MallocCString(tableName);
}

int32_t RdbStoreImpl::Emit(const char *event)
{
    return rdbStore_->Notify(event);
}

int64_t RdbStoreImpl::Insert(const char *table, ValuesBucket valuesBucket, int32_t conflict, int32_t *errCode)
{
    std::string tableName = table;
    int64_t result;
    NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucket(valuesBucket);
    *errCode = rdbStore_->InsertWithConflictResolution(result, tableName,
        nativeValuesBucket, NativeRdb::ConflictResolution(conflict));
    return result;
}

int64_t RdbStoreImpl::InsertEx(const char *table, ValuesBucketEx valuesBucket, int32_t conflict, int32_t *errCode)
{
    std::string tableName = table;
    int64_t result;
    NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucketEx(valuesBucket);
    *errCode = rdbStore_->InsertWithConflictResolution(result, tableName,
        nativeValuesBucket, NativeRdb::ConflictResolution(conflict));
    return result;
}

void RdbStoreImpl::ExecuteSql(const char *sql, int32_t *errCode)
{
    *errCode = rdbStore_->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>());
}

int32_t RdbStoreImpl::CleanDirtyData(const char *tableName, uint64_t cursor)
{
    int32_t rtnCode = rdbStore_->CleanDirtyData(tableName, cursor);
    return rtnCode;
}

int32_t RdbStoreImpl::BatchInsert(int64_t &insertNum, const char *tableName, ValuesBucket *valuesBuckets,
    int64_t valuesSize)
{
    std::vector<NativeRdb::ValuesBucket> valuesVector;
    std::string tableNameStr = tableName;
    if (tableNameStr.empty()) {
        return RelationalStoreJsKit::E_PARAM_ERROR;
    }
    for (int64_t i = 0; i < valuesSize; i++) {
        NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucket(valuesBuckets[i]);
        valuesVector.push_back(nativeValuesBucket);
    }
    int32_t rtnCode = rdbStore_->BatchInsert(insertNum, tableNameStr, valuesVector);
    return rtnCode;
}

int32_t RdbStoreImpl::BatchInsertEx(int64_t &insertNum, const char *tableName, ValuesBucketEx *valuesBuckets,
    int64_t valuesSize)
{
    std::vector<NativeRdb::ValuesBucket> valuesVector;
    std::string tableNameStr = tableName;
    if (tableNameStr.empty()) {
        return RelationalStoreJsKit::E_PARAM_ERROR;
    }
    for (int64_t i = 0; i < valuesSize; i++) {
        NativeRdb::ValuesBucket nativeValuesBucket = ConvertFromValueBucketEx(valuesBuckets[i]);
        valuesVector.push_back(nativeValuesBucket);
    }
    int32_t rtnCode = rdbStore_->BatchInsert(insertNum, tableNameStr, valuesVector);
    return rtnCode;
}

CArrSyncResult RdbStoreImpl::Sync(int32_t mode, RdbPredicatesImpl &predicates)
{
    DistributedRdb::SyncOption option;
    option.mode = static_cast<DistributedRdb::SyncMode>(mode);
    option.isBlock = true;
    DistributedRdb::SyncResult resMap;
    rdbStore_->Sync(option, *(predicates.GetPredicates()),
        [&resMap](const DistributedRdb::SyncResult &result) { resMap = result; });
    if (resMap.size() == 0) {
        return CArrSyncResult{ nullptr, nullptr, -1 };
    }
    char **resultStr = static_cast<char**>(malloc(resMap.size() * sizeof(char*)));
    int32_t *resultNum = static_cast<int32_t*>(malloc(resMap.size() * sizeof(int32_t)));
    if (resultStr == nullptr || resultNum == nullptr) {
        free(resultStr);
        free(resultNum);
        return CArrSyncResult{ nullptr, nullptr, -1 };
    }
    size_t i = 0;
    for (auto it = resMap.begin(); it != resMap.end(); ++it) {
        resultStr[i] = MallocCString(it->first);
        resultNum[i] = it->second;
        i++;
    }
    return CArrSyncResult{resultStr, resultNum, int64_t(resMap.size())};
}

std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::QuerySql(const char *sql, ValueType *bindArgs, int64_t size)
{
    std::string tmpSql = sql;
    std::vector<NativeRdb::ValueObject> tmpBindArgs = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < size; i++) {
        tmpBindArgs.push_back(ValueTypeToValueObject(bindArgs[i]));
    }
    auto result = rdbStore_->QueryByStep(tmpSql, tmpBindArgs);
    return result;
}

std::shared_ptr<NativeRdb::ResultSet> RdbStoreImpl::QuerySqlEx(const char *sql, ValueTypeEx *bindArgs, int64_t size)
{
    std::string tmpSql = sql;
    std::vector<NativeRdb::ValueObject> tmpBindArgs = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < size; i++) {
        tmpBindArgs.push_back(ValueTypeExToValueObject(bindArgs[i]));
    }
    auto result = rdbStore_->QueryByStep(tmpSql, tmpBindArgs);
    return result;
}

void RdbStoreImpl::ExecuteSql(const char *sql, ValueType *bindArgs, int64_t bindArgsSize, int32_t *errCode)
{
    std::vector<NativeRdb::ValueObject> bindArgsObjects = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < bindArgsSize; i++) {
        bindArgsObjects.push_back(ValueTypeToValueObject(bindArgs[i]));
    }
    *errCode = rdbStore_->ExecuteSql(sql, bindArgsObjects);
}

void RdbStoreImpl::ExecuteSqlEx(const char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize, int32_t *errCode)
{
    std::vector<NativeRdb::ValueObject> bindArgsObjects = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < bindArgsSize; i++) {
        bindArgsObjects.push_back(ValueTypeExToValueObject(bindArgs[i]));
    }
    *errCode = rdbStore_->ExecuteSql(sql, bindArgsObjects);
}

int32_t RdbStoreImpl::CloudSync(int32_t mode, CArrStr tables, int64_t callbackId)
{
    DistributedRdb::SyncOption option;
    option.mode = static_cast<DistributedRdb::SyncMode>(mode);
    option.isBlock = false;
    std::vector<std::string> arr = CArrStrToVector(tables);
    auto cFunc = reinterpret_cast<void(*)(CProgressDetails details)>(callbackId);
    auto async = [ lambda = CJLambda::Create(cFunc)](const DistributedRdb::Details &details) ->
        void { lambda(ToCProgressDetails(details)); };
    int32_t errCode = rdbStore_->Sync(option, arr, async);
    return errCode;
}

int32_t RdbStoreImpl::GetVersion(int32_t& errCode)
{
    int32_t version = 0;
    errCode = rdbStore_->GetVersion(version);
    return version;
}

void RdbStoreImpl::SetVersion(int32_t value, int32_t &errCode)
{
    errCode = rdbStore_->SetVersion(value);
}

ModifyTime RdbStoreImpl::GetModifyTime(char *cTables, char *cColumnName, CArrPRIKeyType &cPrimaryKeys,
    int32_t& errCode)
{
    std::string tableName = cTables;
    std::string columnName = cColumnName;
    std::vector<NativeRdb::RdbStore::PRIKey> keys = CArrPRIKeyTypeToPRIKeyArray(cPrimaryKeys);
    std::map<NativeRdb::RdbStore::PRIKey, NativeRdb::RdbStore::Date> map =
        rdbStore_->GetModifyTime(tableName, columnName, keys);
    if (map.empty()) {
        errCode = NativeRdb::E_ERROR;
        return ModifyTime{ 0 };
    }
    return MapToModifyTime(map, errCode);
}

int32_t RdbStoreImpl::GetRebuilt()
{
    auto rebuilt = NativeRdb::RebuiltType::NONE;
    rdbStore_->GetRebuilt(rebuilt);
    return static_cast<int32_t>(rebuilt);
}
}
}