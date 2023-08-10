/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "rdb_sql_utils.h"
#include "relational_cursor.h"
#include "relational_store_error_code.h"
#include "relational_predicates.h"
#include "relational_store_impl.h"
#include "relational_predicates_objects.h"
#include "relational_values_bucket.h"
#include "sqlite_global_config.h"

using namespace OHOS::RdbNdk;
constexpr int RDB_STORE_CID = 1234560; // The class id used to uniquely identify the OH_Rdb_Store class.
OH_VObject *OH_Rdb_CreateValueObject()
{
    return new (std::nothrow) RelationalPredicatesObjects();
}

OH_VBucket *OH_Rdb_CreateValuesBucket()
{
    return new (std::nothrow) RelationalValuesBucket();
}

OH_Predicates *OH_Rdb_CreatePredicates(const char *table)
{
    if (table == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) RelationalPredicate(table);
}

OHOS::RdbNdk::RelationalStore::RelationalStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> store) : store_(store)
{
    id = RDB_STORE_CID;
}

class MainOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
};

int MainOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &rdbStore)
{
    return OHOS::NativeRdb::E_OK;
}

int MainOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}

RelationalStore *GetRelationalStore(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != RDB_STORE_CID) {
        LOG_ERROR("store is invalid. is null %{public}d", (store == nullptr));
        return nullptr;
    }
    return static_cast<RelationalStore *>(store);
}

OH_Rdb_Store *OH_Rdb_GetOrOpen(const OH_Rdb_Config *config, int *errCode)
{
    if (config == nullptr || config->selfSize != sizeof(OH_Rdb_Config) || errCode == nullptr) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d and config size is %{public}zu or "
                  "errCode is NULL ? %{public}d ",
            (config == nullptr), sizeof(OH_Rdb_Config), (errCode == nullptr));
        return nullptr;
    }

    std::string realPath = OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir,
        config->storeName, *errCode);
    if (*errCode != 0) {
        LOG_ERROR("Get database path failed, ret %{public}d ", *errCode);
        return nullptr;
    }
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(realPath);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);
    if (config->bundleName != nullptr) {
        rdbStoreConfig.SetBundleName(config->bundleName);
    }
    rdbStoreConfig.SetName(config->storeName);

    MainOpenCallback callback;
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, -1, callback, *errCode);
    if (store == nullptr) {
        LOG_ERROR("Get RDB Store fail %{public}s", realPath.c_str());
        return nullptr;
    }
    return new (std::nothrow) RelationalStore(store);
}

int OH_Rdb_CloseStore(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete rdbStore;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Rdb_DeleteStore(const OH_Rdb_Config *config)
{
    if (config == nullptr || config->dataBaseDir == nullptr || config->storeName == nullptr) {
        LOG_ERROR("Parameters set error:path is NULL ? %{public}d", (config == nullptr));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int errCode = OHOS::NativeRdb::E_OK;
    std::string realPath = OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(config->dataBaseDir,
        config->storeName, errCode);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    return OHOS::NativeRdb::RdbHelper::DeleteRdbStore(realPath);
}

int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_VBucket *valuesBucket)
{
    auto rdbStore = GetRelationalStore(store);
    auto bucket = RelationalValuesBucket::GetSelf(valuesBucket);
    if (rdbStore == nullptr || table == nullptr || bucket == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int64_t rowId = -1;
    rdbStore->GetStore()->Insert(rowId, table, bucket->Get());
    return rowId >= 0 ? rowId : OH_Rdb_ErrCode::RDB_ERR;
}

int OH_Rdb_Update(OH_Rdb_Store *store, OH_VBucket *valueBucket, OH_Predicates *predicates)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    auto bucket = RelationalValuesBucket::GetSelf(valueBucket);
    if (rdbStore == nullptr || predicate == nullptr || bucket == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int updatedRows = -1;
    rdbStore->GetStore()->Update(updatedRows, bucket->Get(), predicate->Get());
    return updatedRows >= 0 ? updatedRows : OH_Rdb_ErrCode::RDB_ERR;
}

int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicates)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int deletedRows = -1;
    rdbStore->GetStore()->Delete(deletedRows, predicate->Get());
    return deletedRows >= 0 ? deletedRows : OH_Rdb_ErrCode::RDB_ERR;
}

OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length)
{
    auto rdbStore = GetRelationalStore(store);
    auto predicate = RelationalPredicate::GetSelf(predicates);
    if (rdbStore == nullptr || predicate == nullptr) {
        return nullptr;
    }
    std::vector<std::string> columns;
    if (columnNames != nullptr && length > 0) {
        columns.reserve(length);
        for (int i = 0; i < length; i++) {
            columns.push_back(columnNames[i]);
        }
    }

    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        rdbStore->GetStore()->QueryByStep(predicate->Get(), columns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    return new (std::nothrow) RelationalCursor(std::move(resultSet));
}

OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        rdbStore->GetStore()->QuerySql(sql, std::vector<std::string>{});
    if (resultSet == nullptr) {
        return nullptr;
    }
    return new OHOS::RdbNdk::RelationalCursor(std::move(resultSet));
}

int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || sql == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>{});
}

int OH_Rdb_BeginTransaction(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->BeginTransaction();
}

int OH_Rdb_RollBack(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->RollBack();
}

int OH_Rdb_Commit(OH_Rdb_Store *store)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->Commit();
}

int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || databasePath == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->Backup(databasePath);
}

int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || databasePath == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->Restore(databasePath);
}

int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr || version == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->GetVersion(*version);
}

int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version)
{
    auto rdbStore = GetRelationalStore(store);
    if (rdbStore == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return rdbStore->GetStore()->SetVersion(version);
}