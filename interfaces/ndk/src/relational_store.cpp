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

#include "relational_store.h"

#include "relational_cursor_impl.h"
#include "relational_predicates_impl.h"
#include "relational_store_impl.h"

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "relational_values_bucket_impl.h"
#include "relational_error_code.h"
#include "sqlite_global_config.h"
#include "ndk_logger.h"
using OHOS::RdbNdk::RDB_NDK_LABEL;

OHOS::RdbNdk::StoreImpl::StoreImpl(std::shared_ptr<OHOS::NativeRdb::RdbStore> store)
{
    id = RDB_STORE_CID;
    store_ = store;
}

std::shared_ptr<OHOS::NativeRdb::RdbStore> OHOS::RdbNdk::StoreImpl::GetStore()
{
    return store_;
}

class MainOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
};

int MainOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &store)
{
    return OHOS::NativeRdb::E_OK;
}

int MainOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}

OH_Rdb_Store *OH_Rdb_GetOrOpen(const OH_Rdb_Config *config, int *errCode)
{
    if (config == nullptr) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d", (config == nullptr));
        return nullptr;
    }
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(config->path);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);

    MainOpenCallback callback;

    std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
        OHOS::NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, -1, callback, *errCode);
    if (store == nullptr) {
        return nullptr;
    }
    return new OHOS::RdbNdk::StoreImpl(store);
}

int OH_Rdb_CloseStore(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:config is NULL ? %{public}d", (store == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    delete tempStore;
    tempStore = nullptr;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_Rdb_DeleteStore(const char *path)
{
    if (path == nullptr) {
        LOG_ERROR("Parameters set error:path is NULL ? %{public}d", (path == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int err = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(path);
    if (err != OHOS::NativeRdb::E_OK) {
        return err;
    }
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_Rdb_VBucket *valuesBucket)
{
    if (store == nullptr || table == nullptr || valuesBucket == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, table is NULL ? %{public}d,"
                  "valuesBucket is NULL ? %{public}d",
                 (store == nullptr), (table == nullptr), (valuesBucket == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int64_t rowId = -1;
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    auto valueImpl = static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(valuesBucket);
    tempStore->GetStore()->Insert(rowId, table, valueImpl->getValuesBucket());
    return rowId >= 0 ? rowId : OH_Rdb_ErrCode::RDB_ERR;
}

int OH_Rdb_Update(OH_Rdb_Store *store, OH_Rdb_VBucket *valueBucket, OH_Predicates *predicates)
{
    if (store == nullptr || predicates == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, valueBucket is NULL ? %{public}d,"
                  "predicates is NULL ? %{public}d",
                 (store == nullptr), (valueBucket == nullptr), (predicates == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int updatedRows = -1;
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    auto tempPredicate = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    auto valueImpl = static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(valueBucket);

    tempStore->GetStore()->Update(updatedRows, valueImpl->getValuesBucket(), (tempPredicate->GetPredicates()));
    return updatedRows >= 0 ? updatedRows : OH_Rdb_ErrCode::RDB_ERR;
}

int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicates)
{
    if (store == nullptr || predicates == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, predicates is NULL ? %{public}d",
                 (store == nullptr), (predicates == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    int deletedRows = -1;
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    auto tempPredicate = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    tempStore->GetStore()->Delete(deletedRows, (tempPredicate->GetPredicates()));
    return deletedRows >= 0 ? deletedRows : OH_Rdb_ErrCode::RDB_ERR;
}

OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length)
{
    if (store == nullptr || predicates == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID
        || length > OHOS::NativeRdb::GlobalExpr::SQLITE_MAX_COLUMN) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, predicates is NULL ? %{public}d,"
                  "length is %{public}d", (store == nullptr), (predicates == nullptr), length);
        return nullptr;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    auto tempPredicate = static_cast<OHOS::RdbNdk::PredicateImpl *>(predicates);
    std::vector<std::string> columns;
    if (columnNames != nullptr) {
        columns.reserve(length);
        for (int i = 0; i < length; i++) {
            columns.push_back(columnNames[i]);
        }
    }

    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        tempStore->GetStore()->QueryByStep(tempPredicate->GetPredicates(), columns);
    if (resultSet == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> retParam = std::move(resultSet);
    return new OHOS::RdbNdk::CursorImpl(retParam);
}

OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql)
{
    if (store == nullptr || sql == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, sql is NULL ? %{public}d",
                 (store == nullptr), (sql == nullptr));
        return nullptr;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    std::unique_ptr<OHOS::NativeRdb::ResultSet> resultSet =
        tempStore->GetStore()->QuerySql(sql, std::vector<std::string>{});
    if (resultSet == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OHOS::NativeRdb::ResultSet> retParam = std::move(resultSet);
    return new OHOS::RdbNdk::CursorImpl(retParam);
}

int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql)
{
    if (store == nullptr || sql == nullptr ||store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, sql is NULL ? %{public}d",
                 (store == nullptr), (sql == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    return tempStore->GetStore()->ExecuteSql(sql, std::vector<OHOS::NativeRdb::ValueObject>{});
}

int OH_Rdb_BeginTransaction(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d", (store == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    return tempStore->GetStore()->BeginTransaction();
}

int OH_Rdb_RollBack(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d", (store == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    return tempStore->GetStore()->RollBack();
}

int OH_Rdb_Commit(OH_Rdb_Store *store)
{
    if (store == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d", (store == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    return tempStore->GetStore()->Commit();
}

int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath)
{
    if (store == nullptr || databasePath == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, databasePath is NULL ? %{public}d",
                 (store == nullptr), (databasePath == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);

    return tempStore->GetStore()->Backup(databasePath);
}

int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath)
{
    if (store == nullptr || databasePath == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d, databasePath is NULL ? %{public}d",
                 (store == nullptr), (databasePath == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);

    return tempStore->GetStore()->Restore(databasePath);
}

int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version)
{
    if (store == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d", (store == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    return tempStore->GetStore()->GetVersion(*version);
}

int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version)
{
    if (store == nullptr || store->id != OHOS::RdbNdk::RDB_STORE_CID) {
        LOG_ERROR("Parameters set error:store is NULL ? %{public}d", (store == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto tempStore = static_cast<OHOS::RdbNdk::StoreImpl *>(store);
    return tempStore->GetStore()->SetVersion(version);
}